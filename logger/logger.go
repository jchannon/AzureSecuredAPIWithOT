package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Log variable is a globally accessible variable which will be initialized when the InitializeZapCustomLogger function is executed successfully.
	Log *zap.Logger
)

/*
InitializeZapCustomLogger Funtion initializes a logger using uber-go/zap package in the application.
*/
func InitializeZapCustomLogger() {
	conf := zap.Config{
		Encoding:    "json",
		Level:       zap.NewAtomicLevelAt(zapcore.InfoLevel),
		OutputPaths: []string{"stdout"},
		EncoderConfig: zapcore.EncoderConfig{
			LevelKey:     "level",
			TimeKey:      "time",
			CallerKey:    "file",
			MessageKey:   "msg",
			EncodeLevel:  zapcore.LowercaseLevelEncoder,
			EncodeTime:   zapcore.ISO8601TimeEncoder,
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}
	foo, err := conf.Build()
	if err != nil {

	}
	Log = foo
}
