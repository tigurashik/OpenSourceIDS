package Analyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/gopacket"
)

type Analyzer struct {
	Packet   gopacket.Packet
	WarnData []string
}

func (a *Analyzer) IsMenace() bool {
	packetString := a.Packet.String()

	for _, warn := range a.WarnData {
		if strings.Contains(packetString, warn) {
			go a.sendWebhook()
			return true
		}
	}

	return false
}

func (a *Analyzer) sendWebhook() error {
	data := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title": "Warning! Threat detected!",
				"color": 16205896,
				"fields": []map[string]interface{}{
					{
						"name":  "Packet string:",
						"value": "```" + a.Packet.String() + "```",
					},
					{
						"name":  "Warn data:",
						"value": "```" + strings.Join(a.WarnData, ", ") + "```",
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
		resp, err := http.Post("https://discordapp.com/api/webhooks/1238244636921823313/UH65LN7pmV465jc2I8YBrxWcmXicSAv-EuApXDrJ2m_TfAfnyJf5VNFYU_5w0HDXbmAX", "application/json", bytes.NewBuffer(payload))
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
