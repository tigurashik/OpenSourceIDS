package notificator

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type Notificator struct {
	dswebhook string
}

func (n *Notificator) sendWebhook(PacketString string, WarnData string) error {
	data := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title": "Warning! Threat detected!",
				"color": 16205896,
				"fields": []map[string]interface{}{
					{
						"name":  "Packet string:",
						"value": "```" + PacketString + "```",
					},
					{
						"name":  "Warn data:",
						"value": "```" + WarnData + "```",
					},
				},
			},
		},
		"username": "Open Source IDS",
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	send := func() error {
		resp, err := http.Post(n.dswebhook, "application/json", bytes.NewBuffer(payload))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return errors.New("Ошибка отправки Discord Webhook:  " + resp.Status)
		}

		return nil
	}

	for {
		err := send()
		if err == nil {
			break
		}

		time.Sleep(5 * time.Minute)
	}

	return nil
}
