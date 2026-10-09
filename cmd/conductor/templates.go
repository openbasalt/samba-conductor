package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/openbasalt/samba-conductor-idp/branding"
	"github.com/openbasalt/samba-conductor/internal/config"
	"github.com/openbasalt/samba-conductor/internal/i18n"
	"github.com/openbasalt/samba-conductor/internal/mail"
	"github.com/openbasalt/samba-conductor/internal/web"
)

const templatesUsage = "usage: conductor templates list | show NAME | show mail/FILE | check [--config FILE]"

// cmdTemplates lists, shows and checks the template overrides of the
// self-service pages and of the messages (branding.templates_dir and its
// mail directory).
func cmdTemplates(args []string) error {
	if len(args) < 1 {
		return errors.New(templatesUsage)
	}
	switch args[0] {
	case "list":
		for _, p := range web.BuiltinPartials() {
			fmt.Printf("%-12s %-16s base=%s  %s\n", p.Name, p.File, p.Base(), p.Doc)
			fmt.Printf("    required: %s\n", strings.Join(p.Required, " "))
		}
		fmt.Println("messages (overrides in <templates_dir>/mail/, one file per template, language and form):")
		for _, name := range mail.Templates {
			var files []string
			for _, lang := range i18n.Languages {
				files = append(files, "mail/"+name+"."+lang+".txt", "mail/"+name+"."+lang+".html")
			}
			fmt.Printf("%-18s %s\n", name, strings.Join(files, " "))
		}
		fmt.Printf("    placeholders: %s\n", strings.Join(mail.Placeholders(), " "))
		return nil
	case "show":
		if len(args) != 2 {
			return errors.New(templatesUsage)
		}
		if file, ok := strings.CutPrefix(args[1], "mail/"); ok {
			src, ok := mail.BuiltinSource(file)
			if !ok {
				return fmt.Errorf("unknown message template %q (see conductor templates list)", args[1])
			}
			fmt.Print(src)
			return nil
		}
		for _, p := range web.BuiltinPartials() {
			if p.Name == args[1] || p.File == args[1] {
				fmt.Println(p.Header())
				fmt.Print(p.Source)
				return nil
			}
		}
		return fmt.Errorf("unknown partial %q (see conductor templates list)", args[1])
	case "check":
		fs := flag.NewFlagSet("templates check", flag.ExitOnError)
		cfgPath := fs.String("config", config.DefaultPath, "configuration file")
		_ = fs.Parse(args[1:])
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		if cfg.Branding.TemplatesDir == "" {
			fmt.Println("templates: no override directory (branding.templates_dir)")
			return nil
		}
		findings, err := web.CheckTemplates(cfg)
		if err != nil {
			return err
		}
		if len(findings) == 0 {
			fmt.Println("templates: " + cfg.Branding.TemplatesDir + " has no overrides")
		}
		problems := 0
		for _, f := range findings {
			fmt.Println("templates: " + f.String())
			if f.Level != branding.LevelOK {
				problems++
			}
		}
		if problems > 0 {
			return fmt.Errorf("templates: %d override(s) refused or to review", problems)
		}
		return nil
	}
	return errors.New(templatesUsage)
}
