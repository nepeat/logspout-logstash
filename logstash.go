package logstash

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"regexp"
	"strings"
	"os"

	"github.com/gliderlabs/logspout/router"
)

func init() {
	router.AdapterFactories.Register(NewAdapter, "logstash")
}

var regexps = []*regexp.Regexp{
	regexp.MustCompile(`^\s`),
	regexp.MustCompile(`line \d+, in .+`),
}

// Adapter is an adapter that streams UDP JSON to Logstash.
type Adapter struct {
	conn  net.Conn
	route *router.Route
}

// NewAdapter creates an Adapter with UDP as the default transport.
func NewAdapter(route *router.Route) (router.LogAdapter, error) {
	transport, found := router.AdapterTransports.Lookup(route.AdapterTransport("udp"))
	if !found {
		return nil, errors.New("unable to find adapter: " + route.Adapter)
	}

	conn, err := transport.Dial(route.Address, route.Options)
	if err != nil {
		return nil, err
	}

	return &Adapter{
		route: route,
		conn:  conn,
	}, nil
}

// MergeMessages merges an array of Message into a string
func MergeMessages(messages []Message) string {
	var strs = make([]string, 0)

	for _, x := range messages {
		strs = append(strs, x.Message)
	}

	return strings.Join(strs, "\n")
}

// GetTags decides if a message array should be tagged multiline.
func GetTags (messages []Message) []string {
	var tags = make([]string, 0)

	if len(messages) > 1 {
		tags = append(tags, "multiline")
	} else {
		tags = append(tags, "")
	}

	return tags
}

// IsMultiline is a function that determines if a string should be in the queue map.
func IsMultiline(message string) bool {
	for _, expression := range regexps {
		if expression.Match([]byte(message)) == true {
			return true;
		}
	}

	return false;
}

// GetHostname gets the HOSTNAME variable or the container's hostname.
func GetHostname() string {
	hostname := os.Getenv("HOSTNAME")

	if hostname == "" {
		log.Println("logstash: Defaulting to container hostname.")
		hostname, err := os.Hostname()
		if err != nil {
			log.Println("logstash_hostname:", err)
		}
		return hostname
	}
	return hostname
}

// Stream implements the router.LogAdapter interface.
func (a *Adapter) Stream(logstream chan *router.Message) {
	queue := make(map[string][]Message)

	hostname := GetHostname()

	for m := range logstream {
		rawMessage := Message{
			Message:  m.Data,
		}
		finalMessage := Message{}

		_, existing := queue[m.Container.ID];

		// Create an empty slice if there is no queue slice.
		if !existing {
			queue[m.Container.ID] = []Message{}
		}

		if IsMultiline(m.Data) {
			queue[m.Container.ID] = append(queue[m.Container.ID], rawMessage)
			continue
		} else {
			if len(queue[m.Container.ID]) == 0 {
				queue[m.Container.ID] = append(queue[m.Container.ID], rawMessage)
				continue
			} else {
				// remove trailing slash from container name
				containerName := strings.TrimLeft(m.Container.Name, "/")

				finalMessage = Message{
					Message: MergeMessages(queue[m.Container.ID]),
					Name: containerName,
					ID: m.Container.ID,
					Image: m.Container.Config.Image,
					Hostname: m.Container.Config.Hostname,
					Stream: m.Source,
					Tags: GetTags(queue[m.Container.ID]),
					Host: hostname,
				}
				queue[m.Container.ID] = []Message{}
			}
		}

		// Mashal the message into JSON.
		js, err := json.Marshal(finalMessage)
		if err != nil {
			log.Println("logstash_marshal:", err)
			continue
		}

		// Write the message to the Logstash server.
		_, err = a.conn.Write(js)
		if err != nil {
			log.Println("logstash_write:", err)
			continue
		}
	}
}

// Message is a simple JSON input to Logstash.
type Message struct {
	Message  string   `json:"message"`
	Name     string   `json:"container_name"`
	ID       string   `json:"container_id"`
	Image    string   `json:"image_name"`
	Hostname string   `json:"container_hostname"`
	Host     string   `json:"host"`
	Stream   string   `json:"stream"`
	Tags     []string `json:"tags"`
}
