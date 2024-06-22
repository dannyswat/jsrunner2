package models

type ActionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func SuccessResponse() *ActionResponse {
	return &ActionResponse{Success: true, Message: ""}
}

func ErrorResponse(message string) *ActionResponse {
	return &ActionResponse{Success: false, Message: message}
}
