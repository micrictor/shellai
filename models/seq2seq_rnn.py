import torch
import torch.nn as nn
import torch.nn.functional as F
import random
import math

class EncoderRNN(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim, num_layers=2, dropout=0.1, pretrained_embeddings=None, padding_idx=0):
        super(EncoderRNN, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=padding_idx)
        if pretrained_embeddings is not None:
            # Transfer learning: load pretrained embedding matrix
            self.embedding.weight.data.copy_(torch.tensor(pretrained_embeddings, dtype=torch.float32))
            
        self.gru = nn.GRU(
            embed_dim, 
            hidden_dim, 
            num_layers=num_layers, 
            batch_first=True, 
            bidirectional=True, 
            dropout=dropout if num_layers > 1 else 0
        )
        self.fc_hidden = nn.Linear(hidden_dim * 2, hidden_dim)

    def forward(self, x, src_lens=None):
        # x: [batch_size, seq_len]
        embedded = self.embedding(x) # [batch_size, seq_len, embed_dim]
        if src_lens is not None:
            packed = nn.utils.rnn.pack_padded_sequence(
                embedded,
                src_lens.detach().cpu(),
                batch_first=True,
                enforce_sorted=False,
            )
            packed_outputs, hidden = self.gru(packed)
            outputs, _ = nn.utils.rnn.pad_packed_sequence(
                packed_outputs,
                batch_first=True,
                total_length=x.size(1),
            )
        else:
            outputs, hidden = self.gru(embedded)
        # outputs: [batch_size, seq_len, hidden_dim * 2]
        # hidden: [num_layers * 2, batch_size, hidden_dim]
        
        # Combine bidirectional hidden states for decoder initialization
        cat_hidden = torch.cat((hidden[-2, :, :], hidden[-1, :, :]), dim=1)
        dec_hidden = torch.tanh(self.fc_hidden(cat_hidden)) # [batch_size, hidden_dim]
        return outputs, dec_hidden


class BahdanauAttention(nn.Module):
    def __init__(self, hidden_dim):
        super(BahdanauAttention, self).__init__()
        self.W_a = nn.Linear(hidden_dim, hidden_dim)
        self.U_a = nn.Linear(hidden_dim * 2, hidden_dim)
        self.V_a = nn.Linear(hidden_dim, 1)

    def forward(self, decoder_hidden, encoder_outputs, source_mask=None):
        # decoder_hidden: [batch_size, hidden_dim]
        # encoder_outputs: [batch_size, seq_len, hidden_dim * 2]
        seq_len = encoder_outputs.size(1)
        
        # Repeat decoder hidden state across sequence length
        hidden_expanded = decoder_hidden.unsqueeze(1).repeat(1, seq_len, 1) # [batch_size, seq_len, hidden_dim]
        
        # Score calculation: V_a * tanh(W_a(hidden) + U_a(encoder_outputs))
        energy = torch.tanh(self.W_a(hidden_expanded) + self.U_a(encoder_outputs))
        scores = self.V_a(energy).squeeze(-1) # [batch_size, seq_len]
        if source_mask is not None:
            scores = scores.masked_fill(~source_mask, torch.finfo(scores.dtype).min)
        
        attn_weights = F.softmax(scores, dim=1) # [batch_size, seq_len]
        context = torch.bmm(attn_weights.unsqueeze(1), encoder_outputs).squeeze(1) # [batch_size, hidden_dim * 2]
        return context, attn_weights


class AttentionDecoderRNN(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim, dropout=0.1, pretrained_embeddings=None, padding_idx=0):
        super(AttentionDecoderRNN, self).__init__()
        self.vocab_size = vocab_size
        self.hidden_dim = hidden_dim
        
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=padding_idx)
        if pretrained_embeddings is not None:
            self.embedding.weight.data.copy_(torch.tensor(pretrained_embeddings, dtype=torch.float32))
        initial_logit_scale = (
            self.embedding.embedding_dim ** -0.5
        ) / self.embedding.weight.detach().std().clamp_min(1e-6).item()
        self.output_logit_scale = nn.Parameter(
            torch.tensor(math.log(initial_logit_scale), dtype=torch.float32)
        )
            
        self.attention = BahdanauAttention(hidden_dim)
        self.gru = nn.GRU(embed_dim + hidden_dim * 2, hidden_dim, batch_first=True)
        self.output_feature_projection = nn.Linear(
            hidden_dim + hidden_dim * 2 + embed_dim,
            embed_dim,
        )
        self.dropout = nn.Dropout(dropout)

    def forward(self, input_token, decoder_hidden, encoder_outputs, source_mask=None):
        # input_token: [batch_size]
        # decoder_hidden: [batch_size, hidden_dim]
        # encoder_outputs: [batch_size, seq_len, hidden_dim * 2]
        input_token = input_token.unsqueeze(1) # [batch_size, 1]
        embedded = self.dropout(self.embedding(input_token)) # [batch_size, 1, embed_dim]
        
        context, attn_weights = self.attention(
            decoder_hidden, encoder_outputs, source_mask
        ) # context: [batch_size, hidden_dim * 2]
        
        gru_input = torch.cat((embedded, context.unsqueeze(1)), dim=2) # [batch_size, 1, embed_dim + hidden_dim * 2]
        gru_output, hidden = self.gru(gru_input, decoder_hidden.unsqueeze(0))
        # gru_output: [batch_size, 1, hidden_dim]
        
        output_cat = torch.cat((gru_output.squeeze(1), context, embedded.squeeze(1)), dim=1)
        output_features = torch.tanh(
            self.output_feature_projection(output_cat)
        )
        # Reuse the decoder embedding as the vocabulary classifier. This avoids
        # a separate ~41M-parameter projection for the 32K-token T5 vocabulary.
        predictions = F.linear(
            output_features,
            self.embedding.weight,
        ) * self.output_logit_scale.exp().clamp(max=1.0)
        
        return predictions, hidden.squeeze(0), attn_weights


class Seq2SeqAttention(nn.Module):
    def __init__(self, encoder, decoder, pad_idx=0, sos_idx=1, eos_idx=2):
        super(Seq2SeqAttention, self).__init__()
        self.encoder = encoder
        self.decoder = decoder
        self.pad_idx = pad_idx
        self.sos_idx = sos_idx
        self.eos_idx = eos_idx

    def forward(self, src, trg=None, teacher_forcing_ratio=0.5, max_len=128):
        # src: [batch_size, src_len]
        # trg: [batch_size, trg_len]
        batch_size = src.size(0)
        device = src.device
        
        source_mask = src.ne(self.pad_idx)
        encoder_outputs, hidden = self.encoder(src, source_mask.sum(dim=1))
        
        if trg is not None:
            trg_len = trg.size(1)
            outputs = torch.zeros(batch_size, trg_len, self.decoder.vocab_size, device=device)
            input_token = trg[:, 0] # SOS token
            
            for t in range(1, trg_len):
                output, hidden, _ = self.decoder(
                    input_token, hidden, encoder_outputs, source_mask
                )
                outputs[:, t] = output
                teacher_force = random.random() < teacher_forcing_ratio
                top1 = output.argmax(1)
                input_token = trg[:, t] if teacher_force else top1
            return outputs
        else:
            # Greedy Decoding / Generation mode
            decoded_tokens = torch.zeros(batch_size, max_len, dtype=torch.long, device=device)
            input_token = torch.full((batch_size,), self.sos_idx, dtype=torch.long, device=device)
            finished = torch.zeros(batch_size, dtype=torch.bool, device=device)

            for t in range(max_len):
                output, hidden, _ = self.decoder(
                    input_token, hidden, encoder_outputs, source_mask
                )
                top1 = output.argmax(1)
                decoded_tokens[:, t] = top1
                finished |= top1.eq(self.eos_idx)
                if finished.all():
                    break
                input_token = torch.where(
                    finished,
                    torch.full_like(top1, self.eos_idx),
                    top1,
                )
            return decoded_tokens
