package analyzer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

type helperFrameOptions struct {
	corruptChecksum bool
	outOfOrder      bool
	requestID       string
}

type helperWireFrame struct {
	SchemaVersion int    `json:"schemaVersion"`
	Type          string `json:"type"`
	RequestID     string `json:"requestId"`
	ResponseID    string `json:"responseId"`
	Encoding      string `json:"encoding,omitempty"`
	TotalBytes    int64  `json:"totalBytes,omitempty"`
	TotalChunks   int    `json:"totalChunks,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Sequence      *int   `json:"sequence,omitempty"`
	Data          string `json:"data,omitempty"`
}

func writeHelperFramedCompleted(request Request, result any, options helperFrameOptions) {
	requestID := request.RequestID
	if options.requestID != "" {
		requestID = options.requestID
	}
	payload, err := json.Marshal(Response{
		SchemaVersion: protocolSchemaVersion,
		RequestID:     requestID,
		Status:        StatusCompleted,
		Result:        mustMarshalRaw(result),
	})
	if err != nil {
		os.Exit(4)
	}
	writeHelperFramedPayload(requestID, payload, options)
}

func writeHelperFramedPayload(requestID string, payload []byte, options helperFrameOptions) {
	digest := sha256.Sum256(payload)
	checksum := "sha256:" + hex.EncodeToString(digest[:])
	if options.corruptChecksum {
		checksum = "sha256:" + strings.Repeat("0", sha256.Size*2)
	}
	totalBytes := int64(len(payload))
	totalChunks := expectedResponseChunkCount(totalBytes)
	const responseID = "helper-response-1"
	writeHelperFrame(helperWireFrame{
		SchemaVersion: protocolSchemaVersion,
		Type:          responseStartFrame,
		RequestID:     requestID,
		ResponseID:    responseID,
		Encoding:      responseFrameEncoding,
		TotalBytes:    totalBytes,
		TotalChunks:   totalChunks,
		SHA256:        checksum,
	})

	for sequence, offset := 0, 0; offset < len(payload); sequence, offset = sequence+1, offset+responseFrameRawChunkBytes {
		end := offset + responseFrameRawChunkBytes
		if end > len(payload) {
			end = len(payload)
		}
		wireSequence := sequence
		if options.outOfOrder && sequence == 0 {
			wireSequence = 1
		}
		writeHelperFrame(helperWireFrame{
			SchemaVersion: protocolSchemaVersion,
			Type:          responseChunkFrame,
			RequestID:     requestID,
			ResponseID:    responseID,
			Sequence:      &wireSequence,
			Data:          base64.StdEncoding.EncodeToString(payload[offset:end]),
		})
	}
	writeHelperFrame(helperWireFrame{
		SchemaVersion: protocolSchemaVersion,
		Type:          responseEndFrame,
		RequestID:     requestID,
		ResponseID:    responseID,
		TotalBytes:    totalBytes,
		TotalChunks:   totalChunks,
		SHA256:        checksum,
	})
}

func writeHelperOverlongFrame(request Request) {
	writeHelperFrame(helperWireFrame{
		SchemaVersion: protocolSchemaVersion,
		Type:          responseStartFrame,
		RequestID:     request.RequestID,
		ResponseID:    strings.Repeat("a", responseFrameMaxLineBytes),
		Encoding:      responseFrameEncoding,
		TotalBytes:    1,
		TotalChunks:   1,
		SHA256:        "sha256:" + strings.Repeat("0", sha256.Size*2),
	})
}

func writeHelperFrame(frame helperWireFrame) {
	encoded, err := json.Marshal(frame)
	if err != nil {
		os.Exit(4)
	}
	if _, err := os.Stdout.Write(append(encoded, '\n')); err != nil {
		os.Exit(4)
	}
}
