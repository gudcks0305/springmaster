package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

const (
	responseStartFrame = "response-start"
	responseChunkFrame = "response-chunk"
	responseEndFrame   = "response-end"

	responseFrameEncoding      = "base64"
	responseFrameRawChunkBytes = 45 << 10
	responseFrameMaxLineBytes  = 64 << 10
	maxResponseFrameIDBytes    = 64
)

// responseFrame is a JSONL envelope around a bounded slice of one complete
// WorkerResponse JSON value. The entire response is checksummed before the
// embedded response is trusted.
type responseFrame struct {
	SchemaVersion int    `json:"schemaVersion"`
	Type          string `json:"type"`
	RequestID     string `json:"requestId"`
	ResponseID    string `json:"responseId"`
	Encoding      string `json:"encoding"`
	TotalBytes    int64  `json:"totalBytes"`
	TotalChunks   int    `json:"totalChunks"`
	SHA256        string `json:"sha256"`
	Sequence      int    `json:"sequence"`
	Data          string `json:"data"`
}

func (process *workerProcess) readResponse(
	ctx context.Context,
	requestID string,
	maxResponseBytes int,
) (Response, error) {
	line, err := process.readLine(ctx)
	if err != nil {
		return Response{}, err
	}

	frameType, framed, err := classifyResponseEnvelope(line)
	if err != nil {
		return Response{}, err
	}
	if !framed {
		// Older workers send one complete JSON response per line. Keep this
		// compatibility path bounded by MaxLineBytes in the scanner.
		return parseResponse(line, requestID)
	}
	if len(line) > responseFrameMaxLineBytes {
		return Response{}, ErrProtocol
	}
	if frameType != responseStartFrame {
		return Response{}, ErrProtocol
	}

	var start responseFrame
	if err := json.Unmarshal(line, &start); err != nil || !validStartFrame(start, requestID, maxResponseBytes) {
		return Response{}, ErrProtocol
	}

	payload, err := allocateResponsePayload(start.TotalBytes)
	if err != nil {
		return Response{}, ErrProtocol
	}
	digest := sha256.New()
	for sequence := 0; sequence < start.TotalChunks; sequence++ {
		chunkLine, readErr := process.readLine(ctx)
		if readErr != nil {
			return Response{}, readErr
		}
		if len(chunkLine) > responseFrameMaxLineBytes {
			return Response{}, ErrProtocol
		}
		var chunk responseFrame
		if err := json.Unmarshal(chunkLine, &chunk); err != nil {
			return Response{}, ErrProtocol
		}
		decoded, err := decodeChunkFrame(chunk, start, sequence, int64(len(payload)))
		if err != nil {
			return Response{}, ErrProtocol
		}
		payload = append(payload, decoded...)
		_, _ = digest.Write(decoded)
	}

	endLine, err := process.readLine(ctx)
	if err != nil {
		return Response{}, err
	}
	if len(endLine) > responseFrameMaxLineBytes {
		return Response{}, ErrProtocol
	}
	var end responseFrame
	if err := json.Unmarshal(endLine, &end); err != nil || !validEndFrame(end, start) {
		return Response{}, ErrProtocol
	}
	if int64(len(payload)) != start.TotalBytes || !matchesDigest(start.SHA256, digest.Sum(nil)) {
		return Response{}, ErrProtocol
	}
	return parseResponse(payload, requestID)
}

func classifyResponseEnvelope(line []byte) (frameType string, framed bool, err error) {
	var probe struct {
		Type json.RawMessage `json:"type"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return "", false, ErrProtocol
	}
	if len(probe.Type) == 0 || string(probe.Type) == "null" {
		return "", false, nil
	}
	if err := json.Unmarshal(probe.Type, &frameType); err != nil || frameType == "" {
		return "", false, ErrProtocol
	}
	return frameType, true, nil
}

func validStartFrame(frame responseFrame, requestID string, maxResponseBytes int) bool {
	if frame.SchemaVersion != protocolSchemaVersion || frame.Type != responseStartFrame ||
		frame.RequestID != requestID || !validResponseFrameID(frame.ResponseID) ||
		frame.Encoding != responseFrameEncoding || frame.TotalBytes <= 0 ||
		frame.TotalBytes > int64(maxResponseBytes) || !validDigestText(frame.SHA256) {
		return false
	}
	return frame.TotalChunks == expectedResponseChunkCount(frame.TotalBytes)
}

func decodeChunkFrame(
	frame responseFrame,
	start responseFrame,
	sequence int,
	currentBytes int64,
) ([]byte, error) {
	if frame.SchemaVersion != protocolSchemaVersion || frame.Type != responseChunkFrame ||
		frame.RequestID != start.RequestID || frame.ResponseID != start.ResponseID ||
		frame.Sequence != sequence || frame.Data == "" || strings.ContainsAny(frame.Data, "\r\n") ||
		len(frame.Data) > base64.StdEncoding.EncodedLen(responseFrameRawChunkBytes) {
		return nil, ErrProtocol
	}

	decoded, err := base64.StdEncoding.DecodeString(frame.Data)
	if err != nil || len(decoded) == 0 || len(decoded) > responseFrameRawChunkBytes {
		return nil, ErrProtocol
	}
	remaining := start.TotalBytes - currentBytes
	expectedBytes := int64(responseFrameRawChunkBytes)
	if remaining < expectedBytes {
		expectedBytes = remaining
	}
	if expectedBytes <= 0 || int64(len(decoded)) != expectedBytes {
		return nil, ErrProtocol
	}
	return decoded, nil
}

func validEndFrame(frame responseFrame, start responseFrame) bool {
	return frame.SchemaVersion == protocolSchemaVersion && frame.Type == responseEndFrame &&
		frame.RequestID == start.RequestID && frame.ResponseID == start.ResponseID &&
		frame.TotalBytes == start.TotalBytes && frame.TotalChunks == start.TotalChunks &&
		frame.SHA256 == start.SHA256
}

func expectedResponseChunkCount(totalBytes int64) int {
	if totalBytes <= 0 {
		return 0
	}
	return int((totalBytes + responseFrameRawChunkBytes - 1) / responseFrameRawChunkBytes)
}

func allocateResponsePayload(totalBytes int64) ([]byte, error) {
	capacity := int(totalBytes)
	if capacity <= 0 || int64(capacity) != totalBytes {
		return nil, ErrProtocol
	}
	return make([]byte, 0, capacity), nil
}

func validResponseFrameID(value string) bool {
	if len(value) == 0 || len(value) > maxResponseFrameIDBytes {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validDigestText(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	encoded := value[len("sha256:"):]
	for _, character := range encoded {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	decoded, err := hex.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size
}

func matchesDigest(expected string, actual []byte) bool {
	return expected == "sha256:"+hex.EncodeToString(actual)
}
