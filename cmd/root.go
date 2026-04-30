package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/Seann-Moser/krkrxp3/pkg/xp3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type options struct {
	cfgFile        string
	mode           string
	encryption     string
	silent         bool
	flatten        bool
	dumpIndex      bool
	saveTimestamps bool
}

func Execute(ctx context.Context) error {
	opts := options{}

	rootCmd := &cobra.Command{
		Use:           "krkrxp3 [flags] <input> <output>",
		Short:         "Extract and repack KiriKiri XP3 archives",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(2),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig(opts.cfgFile)
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			opts = optionsFromViper(opts.cfgFile)
			configureLogger(opts.silent)
			return validateOptions(opts)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(ctx, opts, args[0], args[1])
		},
	}

	rootCmd.PersistentFlags().StringVar(&opts.cfgFile, "config", "", "config file (default searches current directory and $HOME/.krkrxp3)")
	rootCmd.Flags().StringP("mode", "m", "extract", "operation mode: extract, e, repack, or r")
	rootCmd.Flags().StringP("encryption", "e", xp3.EncryptionNone, "encryption method: "+strings.Join(xp3.EncryptionTypes(), ", "))
	rootCmd.Flags().BoolP("silent", "s", false, "suppress informational logs")
	rootCmd.Flags().BoolP("flatten", "f", false, "pack files into the archive root")
	rootCmd.Flags().BoolP("dump-index", "i", false, "dump the archive file index instead of extracting files")
	rootCmd.Flags().Bool("save-timestamps", false, "store source file modification times when repacking")

	if err := bindFlags(rootCmd); err != nil {
		return err
	}

	return rootCmd.ExecuteContext(ctx)
}

func bindFlags(cmd *cobra.Command) error {
	if err := viper.BindPFlag("config", cmd.PersistentFlags().Lookup("config")); err != nil {
		return err
	}
	for _, key := range []string{"mode", "encryption", "silent", "flatten", "dump-index", "save-timestamps"} {
		if err := viper.BindPFlag(key, cmd.Flags().Lookup(key)); err != nil {
			return err
		}
	}
	return nil
}

func initConfig(cfgFile string) error {
	viper.SetEnvPrefix("KRKRXP3")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName(".krkrxp3")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		if home, err := os.UserHomeDir(); err == nil {
			viper.AddConfigPath(home)
		}
	}

	if err := viper.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if cfgFile != "" || !errors.As(err, &notFound) {
			return fmt.Errorf("read config: %w", err)
		}
	}
	return nil
}

func optionsFromViper(cfgFile string) options {
	return options{
		cfgFile:        cfgFile,
		mode:           viper.GetString("mode"),
		encryption:     viper.GetString("encryption"),
		silent:         viper.GetBool("silent"),
		flatten:        viper.GetBool("flatten"),
		dumpIndex:      viper.GetBool("dump-index"),
		saveTimestamps: viper.GetBool("save-timestamps"),
	}
}

func configureLogger(silent bool) {
	level := slog.LevelInfo
	if silent {
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func validateOptions(opts options) error {
	if !xp3.IsEncryptionType(opts.encryption) {
		return fmt.Errorf("%w: %s", xp3.ErrUnsupportedEncryption, opts.encryption)
	}
	switch opts.mode {
	case "extract", "e", "repack", "r":
		return nil
	default:
		return fmt.Errorf("unsupported mode %q", opts.mode)
	}
}

func run(ctx context.Context, opts options, input string, output string) error {
	switch opts.mode {
	case "extract", "e":
		reader, err := xp3.OpenReader(input)
		if err != nil {
			return err
		}
		defer reader.Close()

		if opts.dumpIndex {
			slog.InfoContext(ctx, "dumping archive index", "input", input, "output", output)
			return reader.DumpIndex(output)
		}

		slog.InfoContext(ctx, "extracting archive", "input", input, "output", output, "files", len(reader.Entries()))
		return reader.ExtractAll(output, xp3.ExtractOptions{
			EncryptionType: opts.encryption,
			Logger:         slog.Default(),
		})
	case "repack", "r":
		writer, err := xp3.CreateWriter(output)
		if err != nil {
			return err
		}

		slog.InfoContext(ctx, "packing archive", "input", input, "output", output)
		if err := writer.AddFolder(input, xp3.AddFolderOptions{
			Flatten:        opts.flatten,
			EncryptionType: opts.encryption,
			SaveTimestamps: opts.saveTimestamps,
			Logger:         slog.Default(),
		}); err != nil {
			closeErr := writer.Close()
			if closeErr != nil {
				slog.ErrorContext(ctx, "failed to close archive after pack error", "error", closeErr)
			}
			return err
		}
		return writer.Close()
	default:
		return fmt.Errorf("unsupported mode %q", opts.mode)
	}
}
