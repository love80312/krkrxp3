package xp3

import (
	"fmt"
	"strconv"
	"strings"
)

type Logger interface {
	Debug(log string, args ...any)
	Info(log string, args ...any)
	Warn(log string, args ...any)
	Error(log string, args ...any)
}

var _ Logger = &StringLogger{}

type LogLevel int

var (
	LogLevelDebug LogLevel = 0
	LogLevelInfo  LogLevel = 1
	LogLevelWarn  LogLevel = 2
	LogLevelError LogLevel = 3
)

type StringLogger struct {
	LogLevel LogLevel
	MaxLogs  int
	Log      []*Log
	watch    chan *Log
}
type Log struct {
	Level LogLevel
	Msg   string
	Args  []any
}

func (s *StringLogger) Watch() chan *Log {
	if s.watch == nil {
		s.watch = make(chan *Log, 1000)
	}
	return s.watch
}
func (s *StringLogger) addLog(log *Log) {
	s.Log = append(s.Log, log)
	if s.watch == nil {
		return
	}
	select {
	case s.watch <- log:
	default:

	}
}

func (s *StringLogger) Debug(log string, args ...any) {
	s.addLog(&Log{
		Level: LogLevelDebug,
		Msg:   log,
		Args:  args,
	})
}

func (s *StringLogger) Info(log string, args ...any) {
	s.addLog(&Log{
		Level: LogLevelInfo,
		Msg:   log,
		Args:  args,
	})
}

func (s *StringLogger) Warn(log string, args ...any) {
	s.addLog(&Log{
		Level: LogLevelWarn,
		Msg:   log,
		Args:  args,
	})
}

func (s *StringLogger) Error(log string, args ...any) {
	s.addLog(&Log{
		Level: LogLevelError,
		Msg:   log,
		Args:  args,
	})
}

func ArgsToKVString(args ...any) string {
	if len(args) == 0 {
		return ""
	}

	var b strings.Builder

	// Rough estimate to reduce reallocs.
	b.Grow(len(args) * 12)

	for i := 0; i < len(args); i += 2 {
		if i > 0 {
			b.WriteByte(' ')
		}

		key := args[i]
		b.WriteString(anyToString(key))
		b.WriteByte('=')

		if i+1 >= len(args) {
			b.WriteString("<missing>")
			break
		}

		b.WriteString(anyToString(args[i+1]))
	}

	return b.String()
}

func anyToString(v any) string {
	switch x := v.(type) {
	case nil:
		return "<nil>"
	case string:
		return x
	case []byte:
		return string(x)
	case fmt.Stringer:
		return x.String()
	case error:
		return x.Error()
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case uint:
		return strconv.FormatUint(uint64(x), 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(x), 'f', -1, 32)
	default:
		return fmt.Sprint(x)
	}
}
