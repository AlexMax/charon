/*
 *  Charon: A game authentication server
 *  Copyright (C) 2016  Alex Mayfield <alexmax2742@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package charon

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/go-ini/ini"
	"goji.io"
	"goji.io/pat"
)

// TemplateDefs defines a map of template names for keys and TemplateNames for
// values
type TemplateDefs map[string]TemplateNames

// TemplateNames defines a list of templates that exist in the "templates/html"
// directory, and end with a ".tmpl" extension.
type TemplateNames []string
type templateStore map[string]*template.Template

var baseTemplates = TemplateDefs{
	"home": TemplateNames{"layout", "header", "home"},
}

// WebApp contains all state for a single instance of the webserver.
type WebApp struct {
	config    *ini.File
	mux       *goji.Mux
	templates templateStore
}

// NewWebApp creates a new instance of the web server app.
func NewWebApp(config *ini.File) (webApp *WebApp, err error) {
	webApp = new(WebApp)

	// Attach configuration
	webApp.config = config

	// Compile templates
	webApp.templates = make(templateStore)
	err = webApp.AddTemplateDefs(&baseTemplates)
	if err != nil {
		return
	}

	// Initialize mux
	webApp.mux = goji.NewMux()

	// Base routes
	webApp.mux.HandleFunc(pat.New("/"), webApp.home)

	return
}

// ListenAndServe has the web server listen on a specific address and port,
// essentially passing straight through to the http method of the same name.
func (webApp *WebApp) ListenAndServe(addr string) (err error) {
	return http.ListenAndServe(addr, webApp.mux)
}

// AddTemplateDefs adds the passed template definitions to the webApp, that can
// therafter be rendered by name by RenderTemplate.
func (webApp *WebApp) AddTemplateDefs(tmpls *TemplateDefs) (err error) {
	for key, value := range *tmpls {
		fqnames := []string{}
		for _, name := range value {
			fqnames = append(fqnames, fmt.Sprintf("templates/html/%s.tmpl", name))
		}
		webApp.templates[key], err = template.ParseFiles(fqnames...)
		if err != nil {
			return
		}
	}
	return
}

// RenderTemplate renders a named template that was previously added by
// AddTemplateDefs.
func (webApp *WebApp) RenderTemplate(res *http.ResponseWriter, name string, data interface{}) {
	tmpl, exists := webApp.templates[name]
	if exists == false {
		http.Error(*res, fmt.Sprintf("template %s does not exist", name), 500)
		return
	}

	err := tmpl.Execute(*res, data)
	if err != nil {
		http.Error(*res, err.Error(), 500)
		return
	}
}

// Renders the homepage.
func (webApp *WebApp) home(res http.ResponseWriter, req *http.Request) {
	webApp.RenderTemplate(&res, "noexist", nil)
}
