package warnhandler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type WarnHandler struct {
	WarnData []string
}

func NewWarnHandler() (*WarnHandler, error) {
	handler := &WarnHandler{}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("Ошибка получения домашней директории: %v", err)
	}

	settingsDir := filepath.Join(homeDir, "Settings")
	settingsPath := filepath.Join(settingsDir, "Settings.json")

	if _, err := os.Stat(settingsDir); os.IsNotExist(err) {
		fmt.Printf("Настройки не обнаружены, создаю экземпляр файла %s\n", settingsDir)
		err := os.MkdirAll(settingsDir, 0755)
		if err != nil {
			return nil, fmt.Errorf("Ошибка создания настроек: %v", err)
		}
		fmt.Printf("Настройки созданы: %s\n", settingsDir)
	}

	if _, err := os.Stat(settingsPath); os.IsNotExist(err) {

		fmt.Printf("Файл настроек не найден, создаю... %s\n", settingsPath)
		handler.WarnData = []string{"55281", "55228"}
		err := handler.saveSettings(settingsPath)
		if err != nil {
			return nil, fmt.Errorf("Ошибка сохранения настроек: %v", err)
		}
		fmt.Printf("Файл настроек создан: %s\n", settingsPath)
	} else {
		fmt.Printf("Загружаю настройки из файла %s\n", settingsPath)
		err := handler.loadSettings(settingsPath)
		if err != nil {
			return nil, fmt.Errorf("Ошибка загрузки настроек: %v", err)
		}
		fmt.Printf("Загружены настройки: %s\n", settingsPath)
	}

	return handler, nil
}

func (h *WarnHandler) saveSettings(filepath string) error {
	data, err := json.Marshal(h.WarnData)
	if err != nil {
		return fmt.Errorf("Ошибка Json WarnData: %v", err)
	}
	err = ioutil.WriteFile(filepath, data, 0644)
	if err != nil {
		return fmt.Errorf("Ошибка записи настроек: %v", err)
	}
	fmt.Printf("Настройки сохранены: %s\n", filepath)
	return nil
}

func (h *WarnHandler) loadSettings(filepath string) error {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("Ошибка чтения: %v", err)
	}
	err = json.Unmarshal(data, &h.WarnData)
	if err != nil {
		return fmt.Errorf("Ошибка json: %v", err)
	}
	fmt.Printf("Настройки успешно загружены %s\n", filepath)
	return nil
}

func (h *WarnHandler) GetWarnData() []string {
	return h.WarnData
}
