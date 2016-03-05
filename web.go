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

type TemplateDefs map[string]TemplateNames
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

func (self *WebApp) ListenAndServe(addr string) (err error) {
	return http.ListenAndServe(addr, self.mux)
}

func (self *WebApp) AddTemplateDefs(tmpls *TemplateDefs) (err error) {
	for key, value := range *tmpls {
		fqnames := []string{}
		for _, name := range value {
			fqnames = append(fqnames, fmt.Sprintf("templates/html/%s.tmpl", name))
		}
		self.templates[key], err = template.ParseFiles(fqnames...)
		if err != nil {
			return
		}
	}
	return
}

func (self *WebApp) home(res http.ResponseWriter, req *http.Request) {
	err := self.templates["home"].Execute(res, nil)
	if err != nil {
		http.Error(res, err.Error(), 500)
	}
}
