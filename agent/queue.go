package main

import "sync"

// urgentEventType returns true if the event should trigger an immediate flush
// rather than waiting for the next periodic tick. For 0 ms real-time streaming,
// every ingested security event triggers an immediate flush to the server.
func urgentEventType(event Event) bool {
	return true
}

type Queue struct {
	mu          sync.Mutex
	events      []Event
	logs        []LogEntry
	maxEvents   int
	maxLogs     int
	dropped     int
	urgentFlush chan<- struct{}
}

func newQueue(maxEvents, maxLogs int) *Queue {
	return &Queue{
		events:    make([]Event, 0, 128),
		logs:      make([]LogEntry, 0, 256),
		maxEvents: maxEvents,
		maxLogs:   maxLogs,
	}
}

// SetUrgentFlush registers the channel that receives a signal whenever a
// high-priority event is added. The main loop listens on this channel to
// flush immediately instead of waiting for the periodic tick.
func (q *Queue) SetUrgentFlush(ch chan<- struct{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.urgentFlush = ch
}

func (q *Queue) AddEvent(event Event) {
	q.mu.Lock()
	if len(q.events) >= q.maxEvents {
		q.events = q.events[1:]
		q.dropped++
	}
	q.events = append(q.events, event)
	uf := q.urgentFlush
	isUrgent := urgentEventType(event)
	q.mu.Unlock()

	// Signal outside the lock to avoid any risk of deadlock.
	if isUrgent && uf != nil {
		select {
		case uf <- struct{}{}:
		default: // channel already has a pending signal, no need to add more
		}
	}
}

func (q *Queue) AddLog(entry LogEntry) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.logs) >= q.maxLogs {
		q.logs = q.logs[1:]
		q.dropped++
	}
	q.logs = append(q.logs, entry)
}

func (q *Queue) Take() ([]Event, []LogEntry) {
	q.mu.Lock()
	defer q.mu.Unlock()
	events := q.events
	logs := q.logs
	q.events = make([]Event, 0, 128)
	q.logs = make([]LogEntry, 0, 256)
	return events, logs
}

func (q *Queue) Len() (int, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.events), len(q.logs)
}
