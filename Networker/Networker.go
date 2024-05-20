package networker

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"main/Analyzer"
	warnhandler "main/WarnHandler"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	_ "modernc.org/sqlite"
)

type Networker struct {
	db *sql.DB
}

type Packet struct {
	Time    string
	Device  string
	Context string
}

func NewNetworker(dbPath string) (*Networker, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	createTables := `
	CREATE TABLE IF NOT EXISTS warnings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		device TEXT,
		packet TEXT
	);
	
	CREATE TABLE IF NOT EXISTS safe (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		device TEXT,
		packet TEXT
	);`

	_, err = db.Exec(createTables)
	if err != nil {
		return nil, err
	}

	return &Networker{db: db}, nil
}

func (n *Networker) GetInter() ([]pcap.Interface, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	return interfaces, nil
}

func (n *Networker) Monitor() error {
	interfaces, err := n.GetInter()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wh, _ := warnhandler.NewWarnHandler()
	for _, iface := range interfaces {
		wg.Add(1)
		go func(iface pcap.Interface) {
			defer wg.Done()
			handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
			if err != nil {
				log.Printf("Ошибка чтения интерфейса: %s: %v", iface.Name, err)
				return
			}
			defer handle.Close()

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				println("Новый пакет обьнаружен! Анализирую...")
				anal := Analyzer.Analyzer{Packet: packet, WarnData: wh.GetWarnData()}
				var tableName string
				if anal.IsMenace() {
					tableName = "warnings"
					println("Обнаружена угроза нарушения правил безопасности!")
				} else {
					tableName = "safe"
					println("Угроза не обнаружена.")
				}
				err := n.retryExec(fmt.Sprintf("INSERT INTO %s (device, packet, time) VALUES (?, ?, CURRENT_TIMESTAMP)", tableName), iface.Name, packet.String())
				if err != nil {
					println("Ошибка загрузки данных пакета: %s: %v", tableName, err)
				}
				println("Пакет добавлен в таблицу ", tableName)
			}
		}(iface)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	wg.Wait()

	return nil
}

func (n *Networker) retryExec(query string, args ...interface{}) error {
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		_, err := n.db.Exec(query, args...)
		if err == nil {
			return nil
		}

		if errors.Is(err, sql.ErrTxDone) || errors.Is(err, sql.ErrConnDone) {
			return err
		}

		if strings.Contains(err.Error(), "База данных заблокирована! ") {
			time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
			continue
		}

		return err
	}

	return fmt.Errorf("Максимальный лимит попыток query достигнут: %s", query)
}

func (n *Networker) AddToWarnings(ctx, device string) error {
	return n.retryExec("INSERT INTO warnings (device, packet, time) VALUES (?, ?, CURRENT_TIMESTAMP)", device, ctx)
}

func (n *Networker) AddToSafe(ctx, device string) error {
	return n.retryExec("INSERT INTO safe (device, packet, time) VALUES (?, ?, CURRENT_TIMESTAMP)", device, ctx)
}

func (n *Networker) GetPackets(table string) ([]Packet, error) {
	rows, err := n.db.Query(fmt.Sprintf("SELECT time, device, packet FROM %s ORDER BY time DESC", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packets []Packet
	for rows.Next() {
		var packet Packet
		if err := rows.Scan(&packet.Time, &packet.Device, &packet.Context); err != nil {
			return nil, err
		}
		packets = append(packets, packet)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return packets, nil
}

func (n *Networker) GetAllPackets() ([]Packet, error) {
	var packets []Packet

	warnings, err := n.GetPackets("warnings")
	if err != nil {
		return nil, err
	}
	packets = append(packets, warnings...)

	safe, err := n.GetPackets("safe")
	if err != nil {
		return nil, err
	}
	packets = append(packets, safe...)

	// Сортировка по времени
	sort.Slice(packets, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339, packets[i].Time)
		tj, _ := time.Parse(time.RFC3339, packets[j].Time)
		return ti.After(tj)
	})

	return packets, nil
}
