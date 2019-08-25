package xlat

import (
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/gorilla/mux"
)

type WebInfo struct {
	Router *mux.Router
}

func (s *WebInfo) PlatTable46Handler(w http.ResponseWriter, r *http.Request) {
	if Ctrl == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("Plat not initialized")))
		return
	}
	content := ""
	for _, v := range Ctrl.Table46 {
		// ip := make([]byte, 4)
		// binary.BigEndian.PutUint32(ip, k)
		v.PortMap.Range(func(key interface{}, value interface{}) bool {
			ipt := value.(*NATuple)
			if time.Since(ipt.LastUsed).Minutes() > ConfigVar.Spec.NATTimeout {
				content += "--"
			}
			if ipt.Port4 != ipt.Port6 {
				content += "!!"
			}
			content += fmt.Sprintf("%+v\n", ipt)
			return true
		})
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
}

func (s *WebInfo) Init() error {
	s.Router = mux.NewRouter()
	s.Router.HandleFunc("/xlat/api/v1/plat/table46", s.PlatTable46Handler).Methods("GET")
	// pprof
	// s.Router.PathPrefix("/debug/pprof/").HandlerFunc(pprof.Index)
	s.Router.HandleFunc("/debug/pprof/", pprof.Index)
	s.Router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	s.Router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	s.Router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	return nil
}

func (s *WebInfo) Serve(host string, port int) error {
	url := fmt.Sprintf("%s:%d", host, port)
	log.Printf("API Serving on %s:%d", host, port)
	err := http.ListenAndServe(url, s.Router)
	if err != nil {
		log.Printf("API server failed: %s", err.Error())
	}
	return err
}
