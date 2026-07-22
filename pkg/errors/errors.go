package errors

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AppError represents a structured API error.
type AppError struct {
	Code    int    `json:"-"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func (e *AppError) Error() string {
	return e.Message
}

// Common errors
var (
	ErrUnauthorized    = &AppError{Code: http.StatusUnauthorized, Message: "unauthorized"}
	ErrForbidden       = &AppError{Code: http.StatusForbidden, Message: "forbidden"}
	ErrNotFound        = &AppError{Code: http.StatusNotFound, Message: "resource not found"}
	ErrBadRequest      = &AppError{Code: http.StatusBadRequest, Message: "bad request"}
	ErrConflict        = &AppError{Code: http.StatusConflict, Message: "resource already exists"}
	ErrInternal        = &AppError{Code: http.StatusInternalServerError, Message: "internal server error"}
	ErrTooManyRequests = &AppError{Code: http.StatusTooManyRequests, Message: "too many requests"}
)

// New creates a new AppError.
func New(code int, message string) *AppError {
	return &AppError{Code: code, Message: message}
}

// WithDetail adds a detail message to an AppError.
func WithDetail(err *AppError, detail string) *AppError {
	return &AppError{Code: err.Code, Message: err.Message, Detail: detail}
}

// Response is the standard API response envelope.
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *AppError   `json:"error,omitempty"`
	Meta    interface{} `json:"meta,omitempty"`
}

// OK sends a successful response.
func OK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{Success: true, Data: data})
}

// Created sends a 201 response.
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, Response{Success: true, Data: data})
}

// OKWithMeta sends a successful response with pagination metadata.
func OKWithMeta(c *gin.Context, data interface{}, meta interface{}) {
	c.JSON(http.StatusOK, Response{Success: true, Data: data, Meta: meta})
}

// Fail sends an error response.
func Fail(c *gin.Context, err *AppError) {
	c.JSON(err.Code, Response{Success: false, Error: err})
}

// FailMsg sends an error response with a custom message.
func FailMsg(c *gin.Context, code int, message string) {
	c.JSON(code, Response{Success: false, Error: &AppError{Code: code, Message: message}})
}

// Internal responds with a generic 500 — the real error is only logged
// server-side (via the global zap logger set in main), never echoed to the
// client, so DB/driver internals can't leak through API error messages.
func Internal(c *gin.Context, err error) {
	zap.L().Error("internal error",
		zap.String("method", c.Request.Method),
		zap.String("path", c.FullPath()),
		zap.Error(err),
	)
	Fail(c, ErrInternal)
}

// Abort sends an error and aborts the gin chain.
func Abort(c *gin.Context, err *AppError) {
	c.AbortWithStatusJSON(err.Code, Response{Success: false, Error: err})
}
