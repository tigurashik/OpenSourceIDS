package main

import (
	"fmt"
	"html/template"
	"log"
	networker "main/Networker"
	"net/http"
	"path/filepath"
)

type TemplateData struct {
	WarningsCount int
	SafeCount     int
	Warnings      []networker.Packet
	Safe          []networker.Packet
}

var tmpl *template.Template

func init() {
	var err error
	tmpl, err = template.ParseFiles(filepath.Join("templates", "template.html"))
	if err != nil {
		log.Fatalf("Error parsing template: %v", err)
	}
}

func main() {
	nh, err := networker.NewNetworker("./network.db")
	if err != nil {
		log.Fatalf("Error creating Networker: %v", err)
	}

	go func() {
		if err := nh.Monitor(); err != nil {
			log.Fatalf("Error monitoring interfaces: %v", err)
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		displayPackets(nh, w, r)
	})

	fmt.Println("Запускаю веб интерфейс на порте :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func displayPackets(nh *networker.Networker, w http.ResponseWriter, r *http.Request) {
	warnings, err := nh.GetPackets("warnings")
	if err != nil {
		http.Error(w, "Ошибка загрузки пакета в warnings:", http.StatusInternalServerError)
		return
	}

	safe, err := nh.GetPackets("safe")
	if err != nil {
		http.Error(w, "Ошибка загрузки пакета в safe:", http.StatusInternalServerError)
		return
	}
	data := TemplateData{
		WarningsCount: len(warnings),
		SafeCount:     len(safe),
		Warnings:      warnings,
		Safe:          safe,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Ошибка рендера html-образца: ", http.StatusInternalServerError)
	}
}
