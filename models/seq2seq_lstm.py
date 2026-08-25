import random
import math

import torch
import torch.nn as nn
import torch.nn.functional as F


class EncoderLSTM(nn.Module):
    def __init__(
        self,
        vocab_size,
        embed_dim,
        hidden_dim,
        num_layers=2,
        dropout=0.1,
        pretrained_embeddings=None,
        padding_idx=0,
    ):
        super().__init__()
        self.embedding = nn.Embedding(
            vocab_size, embed_dim, padding_idx=padding_idx
        )
        if pretrained_embeddings is not None:
            self.embedding.weight.data.copy_(
                torch.as_tensor(pretrained_embeddings, dtype=torch.float32)
            )
        self.lstm = nn.LSTM(
            embed_dim,
            hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.hidden_projection = nn.Linear(hidden_dim * 2, hidden_dim)
        self.cell_projection = nn.Linear(hidden_dim * 2, hidden_dim)

    def forward(self, tokens, source_lengths):
        embedded = self.embedding(tokens)
        packed = nn.utils.rnn.pack_padded_sequence(
            embedded,
            source_lengths.detach().cpu(),
            batch_first=True,
            enforce_sorted=False,
        )
        packed_outputs, (hidden, cell) = self.lstm(packed)
        outputs, _ = nn.utils.rnn.pad_packed_sequence(
            packed_outputs,
            batch_first=True,
            total_length=tokens.size(1),
        )

        # The last two states are the final forward/backward states from the
        # uppermost bidirectional encoder layer.
        hidden = torch.tanh(
            self.hidden_projection(torch.cat((hidden[-2], hidden[-1]), dim=1))
        )
        cell = torch.tanh(
            self.cell_projection(torch.cat((cell[-2], cell[-1]), dim=1))
        )
        return outputs, (hidden, cell)


class BahdanauAttention(nn.Module):
    def __init__(self, hidden_dim):
        super().__init__()
        self.decoder_projection = nn.Linear(hidden_dim, hidden_dim)
        self.encoder_projection = nn.Linear(hidden_dim * 2, hidden_dim)
        self.score_projection = nn.Linear(hidden_dim, 1)

    def forward(self, decoder_hidden, encoder_outputs, source_mask):
        energy = torch.tanh(
            self.decoder_projection(decoder_hidden).unsqueeze(1)
            + self.encoder_projection(encoder_outputs)
        )
        scores = self.score_projection(energy).squeeze(-1)
        scores = scores.masked_fill(
            ~source_mask, torch.finfo(scores.dtype).min
        )
        weights = F.softmax(scores, dim=1)
        context = torch.bmm(weights.unsqueeze(1), encoder_outputs).squeeze(1)
        return context, weights


class AttentionDecoderLSTM(nn.Module):
    def __init__(
        self,
        vocab_size,
        embed_dim,
        hidden_dim,
        dropout=0.1,
        pretrained_embeddings=None,
        padding_idx=0,
    ):
        super().__init__()
        self.vocab_size = vocab_size
        self.embedding = nn.Embedding(
            vocab_size, embed_dim, padding_idx=padding_idx
        )
        if pretrained_embeddings is not None:
            self.embedding.weight.data.copy_(
                torch.as_tensor(pretrained_embeddings, dtype=torch.float32)
            )
        initial_logit_scale = (
            self.embedding.embedding_dim ** -0.5
        ) / self.embedding.weight.detach().std().clamp_min(1e-6).item()
        self.output_logit_scale = nn.Parameter(
            torch.tensor(math.log(initial_logit_scale), dtype=torch.float32)
        )
        self.attention = BahdanauAttention(hidden_dim)
        self.lstm = nn.LSTM(
            embed_dim + hidden_dim * 2,
            hidden_dim,
            batch_first=True,
        )
        self.output_feature_projection = nn.Linear(
            hidden_dim + hidden_dim * 2 + embed_dim, embed_dim
        )
        self.dropout = nn.Dropout(dropout)

    def forward(
        self,
        input_token,
        state,
        encoder_outputs,
        source_mask,
    ):
        hidden, cell = state
        embedded = self.dropout(self.embedding(input_token.unsqueeze(1)))
        context, attention_weights = self.attention(
            hidden, encoder_outputs, source_mask
        )
        decoder_input = torch.cat(
            (embedded, context.unsqueeze(1)), dim=2
        )
        decoder_output, (hidden, cell) = self.lstm(
            decoder_input,
            (hidden.unsqueeze(0), cell.unsqueeze(0)),
        )
        output_features = torch.tanh(self.output_feature_projection(
            torch.cat(
                (
                    decoder_output.squeeze(1),
                    context,
                    embedded.squeeze(1),
                ),
                dim=1,
            )
        ))
        # Weight tying substantially reduces the otherwise dominant
        # vocabulary projection and makes transferred embeddings useful on both
        # the input and output sides.
        logits = F.linear(
            output_features,
            self.embedding.weight,
        ) * self.output_logit_scale.exp().clamp(max=1.0)
        return logits, (hidden.squeeze(0), cell.squeeze(0)), attention_weights


class Seq2SeqAttentionLSTM(nn.Module):
    def __init__(self, encoder, decoder, pad_idx=0, sos_idx=0, eos_idx=1):
        super().__init__()
        self.encoder = encoder
        self.decoder = decoder
        self.pad_idx = pad_idx
        self.sos_idx = sos_idx
        self.eos_idx = eos_idx

    def forward(
        self,
        src,
        trg=None,
        teacher_forcing_ratio=0.5,
        max_len=128,
    ):
        batch_size = src.size(0)
        source_mask = src.ne(self.pad_idx)
        encoder_outputs, state = self.encoder(
            src, source_mask.sum(dim=1)
        )

        if trg is not None:
            target_length = trg.size(1)
            outputs = torch.zeros(
                batch_size,
                target_length,
                self.decoder.vocab_size,
                device=src.device,
            )
            input_token = trg[:, 0]
            for timestep in range(1, target_length):
                logits, state, _ = self.decoder(
                    input_token,
                    state,
                    encoder_outputs,
                    source_mask,
                )
                outputs[:, timestep] = logits
                predicted = logits.argmax(dim=1)
                input_token = (
                    trg[:, timestep]
                    if random.random() < teacher_forcing_ratio
                    else predicted
                )
            return outputs

        decoded = torch.full(
            (batch_size, max_len),
            self.pad_idx,
            dtype=torch.long,
            device=src.device,
        )
        input_token = torch.full(
            (batch_size,),
            self.sos_idx,
            dtype=torch.long,
            device=src.device,
        )
        finished = torch.zeros(
            batch_size, dtype=torch.bool, device=src.device
        )
        for timestep in range(max_len):
            logits, state, _ = self.decoder(
                input_token,
                state,
                encoder_outputs,
                source_mask,
            )
            predicted = logits.argmax(dim=1)
            decoded[:, timestep] = predicted
            finished |= predicted.eq(self.eos_idx)
            if finished.all():
                break
            input_token = torch.where(
                finished,
                torch.full_like(predicted, self.eos_idx),
                predicted,
            )
        return decoded
