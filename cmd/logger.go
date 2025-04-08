package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	// Debug level for detailed information
	Debug LogLevel = iota
	// Info level for general information
	Info
	// Success level for successful operations
	Success
	// Warning level for warning messages
	Warning
	// Error level for error messages
	Error
	// Fatal level for fatal errors that terminate execution
	Fatal
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Success:
		return "SUCCESS"
	case Warning:
		return "WARNING"
	case Error:
		return "ERROR"
	case Fatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// ParseLogLevel parses a string into a LogLevel
func ParseLogLevel(level string) (LogLevel, error) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return Debug, nil
	case "INFO":
		return Info, nil
	case "SUCCESS":
		return Success, nil
	case "WARNING":
		return Warning, nil
	case "ERROR":
		return Error, nil
	case "FATAL":
		return Fatal, nil
	default:
		return Info, fmt.Errorf("unknown log level: %s", level)
	}
}

// Logger provides a consistent logging interface
type Logger struct {
	out      io.Writer
	minLevel LogLevel
}

// New creates a new logger that writes to the provided writer
func New(out io.Writer, minLevel LogLevel) *Logger {
	return &Logger{
		out:      out,
		minLevel: minLevel,
	}
}

// Default returns a logger that writes to stdout with minimum level INFO
func Default() *Logger {
	return New(os.Stdout, Info)
}

// SetMinLevel sets the minimum log level
func (l *Logger) SetMinLevel(level LogLevel) {
	l.minLevel = level
}

// shouldLog returns true if the given level should be logged
func (l *Logger) shouldLog(level LogLevel) bool {
	return level >= l.minLevel
}

// Debug logs a debug message
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.shouldLog(Debug) {
		fmt.Fprintf(l.out, "❓ "+format+"\n", v...)
	}
}

// Info logs an informational message
func (l *Logger) Info(format string, v ...interface{}) {
	if l.shouldLog(Info) {
		fmt.Fprintf(l.out, "🔧 "+format+"\n", v...)
	}
}

// Success logs a success message
func (l *Logger) Success(format string, v ...interface{}) {
	if l.shouldLog(Success) {
		fmt.Fprintf(l.out, "✅ "+format+"\n", v...)
	}
}

// Warning logs a warning message
func (l *Logger) Warning(format string, v ...interface{}) {
	if l.shouldLog(Warning) {
		fmt.Fprintf(l.out, "⚠️ "+format+"\n", v...)
	}
}

// Error logs an error message
func (l *Logger) Error(format string, v ...interface{}) {
	if l.shouldLog(Error) {
		fmt.Fprintf(l.out, "❌ "+format+"\n", v...)
	}
}

// Fatal logs an error message and exits with code 1
func (l *Logger) Fatal(format string, v ...interface{}) {
	if l.shouldLog(Fatal) {
		fmt.Fprintf(l.out, "💀 "+format+"\n", v...)
		os.Exit(1)
	}
}
