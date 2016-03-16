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
	"encoding/gob"
	"fmt"
	"html/template"
	"net/http"

	gcontext "github.com/gorilla/context"
	gsessions "github.com/gorilla/sessions"
	"goji.io"
	"goji.io/pat"
)

// TemplateDefs defines a map of template names for keys and TemplateNames for
// values
type TemplateDefs map[string]TemplateNames

// TemplateNames defines a list of templates that exist in the "templates/html"
// directory, and end with a ".tmpl" extension.
type TemplateNames []string

// FormErrors contains a list of errors keyed on their struct names.
type FormErrors map[string]string

type templateStore map[string]*template.Template

const sessionName = "session"

// WebApp contains all state for a single instance of the webserver.
type WebApp struct {
	config       *Config
	database     *Database
	mux          *goji.Mux
	sessionStore gsessions.Store
	templates    templateStore
}

// NewWebApp creates a new instance of the web server app.
func NewWebApp(config *Config) (webApp *WebApp, err error) {
	webApp = new(WebApp)

	// Attach configuration
	webApp.config = config

	// Initialize database connection
	database, err := NewDatabase(config)
	if err != nil {
		return
	}
	webApp.database = database

	// Initialize mux
	webApp.mux = goji.NewMux()

	// Initialize session store
	webApp.sessionStore = gsessions.NewCookieStore([]byte("secret"))
	gob.Register(User{})

	// Compile templates
	webApp.templates = make(templateStore)
	err = webApp.AddTemplateDefs(&BaseTemplates)
	if err != nil {
		return
	}

	// Clear Context Middleware (needed for sessions)
	webApp.mux.Use(gcontext.ClearHandler)

	// Base routes
	webApp.mux.HandleFunc(pat.New("/"), webApp.Home)
	webApp.mux.HandleFuncC(pat.New("/login"), webApp.Login)
	webApp.mux.Handle(pat.New("/assets/*"), http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))

	return
}

// ListenAndServe has the web server listen on a specific address and port,
// essentially passing straight through to the http method of the same name.
func (webApp *WebApp) ListenAndServe(addr string) (err error) {
	return http.ListenAndServe(addr, webApp.mux)
}

// AddTemplateDefs takes the passed template definitions, figures out where they
// exist on the filesystem, parses them, and puts them in the template store
// for later execution.
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

// RenderTemplate renders a named template from the template store that was
// previously added by AddTemplateDefs.
func (webApp *WebApp) RenderTemplate(res http.ResponseWriter, req *http.Request, name string, data interface{}) {
	tmpl, exists := webApp.templates[name]
	if exists == false {
		http.Error(res, fmt.Sprintf("template %s does not exist", name), 500)
		return
	}

	// Populate template context with session data
	session, err := webApp.sessionStore.Get(req, sessionName)
	if err != nil {
		http.Error(res, err.Error(), 500)
		return
	}

	allData := struct {
		Session map[interface{}]interface{}
		Config  *Config
		Data    interface{}
	}{
		session.Values,
		webApp.config,
		data,
	}

	err = tmpl.Execute(res, allData)
	if err != nil {
		http.Error(res, err.Error(), 500)
		return
	}
}
