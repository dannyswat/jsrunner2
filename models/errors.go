package models

type ServerError struct {
	message string
}

func (e *ServerError) Error() string {
	return e.message
}

func NewServerError(message string) *ServerError {
	return &ServerError{message: message}
}

type UserError struct {
	message string
}

func (e *UserError) Error() string {
	return e.message
}

func NewUserError(message string) *UserError {
	return &UserError{message: message}
}
