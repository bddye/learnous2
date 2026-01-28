package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/version"
	"github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"
)

// main 是程序的入口函数
func main() {
	logger.SetFlags(logger.Lshortfile)

	configFlagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ContinueOnError)

	// 因为我们提前进行解析以确定是 alpha 还是旧版配置，所以目前必须忽略任何未知的标志
	configFlagSet.ParseErrorsAllowlist.UnknownFlags = true

	config := configFlagSet.String("config", "", "path to config file")
	alphaConfig := configFlagSet.String("alpha-config", "", "path to alpha config file (use at your own risk - the structure in this config file may change between minor releases)")
	convertConfig := configFlagSet.Bool("convert-config-to-alpha", false, "if true, the proxy will load configuration as normal and convert existing configuration to the alpha config structure, and print it to stdout")
	showVersion := configFlagSet.Bool("version", false, "print version string")
	configFlagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2-proxy %s (built with %s)\n", version.VERSION, runtime.Version())
		return
	}

	if *convertConfig && *alphaConfig != "" {
		logger.Fatal("cannot use alpha-config and convert-config-to-alpha together")
	}

	opts, err := loadConfiguration(*config, *alphaConfig, configFlagSet, os.Args[1:])
	if err != nil {
		logger.Fatalf("ERROR: %v", err)
	}

	if *convertConfig {
		if err := printConvertedConfig(opts); err != nil {
			logger.Fatalf("ERROR: could not convert config: %v", err)
		}
		return
	}

	if err = validation.Validate(opts); err != nil {
		logger.Fatalf("%s", err)
	}

	validator := NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile)
	oauthproxy, err := NewOAuthProxy(opts, validator)
	if err != nil {
		logger.Fatalf("ERROR: Failed to initialise OAuth2 Proxy: %v", err)
	}

	if err := oauthproxy.Start(); err != nil {
		logger.Fatalf("ERROR: Failed to start OAuth2 Proxy: %v", err)
	}
}

// loadConfiguration 加载用户配置。
// 它将加载 alpha 配置（如果提供了 alphaConfig）或者旧版配置。
func loadConfiguration(config, yamlConfig string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	opts, err := loadLegacyOptions(config, extraFlags, args)
	if err != nil {
		return nil, fmt.Errorf("failed to load legacy options: %w", err)
	}

	if yamlConfig != "" {
		logger.Printf("WARNING: You are using alpha configuration. The structure in this configuration file may change without notice. You MUST remove conflicting options from your existing configuration.")
		opts, err = loadYamlOptions(yamlConfig, config, extraFlags, args)
		if err != nil {
			return nil, fmt.Errorf("failed to load yaml options: %w", err)
		}
	}

	// 加载配置后确保设置默认值
	opts.EnsureDefaults()
	return opts, nil
}

// loadLegacyOptions 使用旧版标志集和旧版选项结构体加载旧的 toml 选项。
func loadLegacyOptions(config string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	optionsFlagSet := options.NewLegacyFlagSet()
	optionsFlagSet.AddFlagSet(extraFlags)
	if err := optionsFlagSet.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %v", err)
	}

	legacyOpts := options.NewLegacyOptions()
	if err := options.Load(config, optionsFlagSet, legacyOpts); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to convert config: %v", err)
	}

	return opts, nil
}

// loadYamlOptions 加载不包括已转换为新 alpha 格式的选项的旧式配置，
// 然后将从 YAML 加载的 alpha 选项合并到核心配置中。
func loadYamlOptions(yamlConfig, config string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	opts, err := loadOptions(config, extraFlags, args)
	if err != nil {
		return nil, fmt.Errorf("failed to load core options: %v", err)
	}

	alphaOpts := options.NewAlphaOptions(opts)
	if err := options.LoadYAML(yamlConfig, alphaOpts); err != nil {
		return nil, fmt.Errorf("failed to load alpha options: %v", err)
	}

	alphaOpts.MergeOptionsWithDefaults(opts)
	return opts, nil
}

// loadOptions 使用旧式格式将配置加载到核心 options.Options 结构体中。
// 这意味着任何已转换为 alpha 配置的选项都不会通过此方法加载。
func loadOptions(config string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {
	optionsFlagSet := options.NewFlagSet()
	optionsFlagSet.AddFlagSet(extraFlags)
	if err := optionsFlagSet.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %v", err)
	}

	opts := options.NewOptions()
	if err := options.Load(config, optionsFlagSet, opts); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	return opts, nil
}

// printConvertedConfig 从加载的配置中提取 alpha 选项，并将其以 YAML 格式渲染到标准输出。
func printConvertedConfig(opts *options.Options) error {
	alphaConfig := options.NewAlphaOptions(opts)

	// 用于加载任意 YAML 结构的通用接口
	var buffer map[string]interface{}

	if err := options.Decode(alphaConfig, &buffer); err != nil {
		return fmt.Errorf("unable to decode alpha config into interface: %w", err)
	}

	data, err := yaml.Marshal(buffer)
	if err != nil {
		return fmt.Errorf("unable to marshal config: %v", err)
	}

	if _, err := os.Stdout.Write(data); err != nil {
		return fmt.Errorf("unable to write output: %v", err)
	}

	return nil
}
