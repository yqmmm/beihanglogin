package lib

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/PuerkitoBio/goquery"
	log "github.com/sirupsen/logrus"
)

type Challenge struct {
	Challenge string `json:"challenge"`
	ClientIp  string `json:"client_ip"`
}

type RAction struct {
	Res      string      `json:"res"`
	Error    string      `json:"error"`
	Ecode    interface{} `json:"ecode"`
	ErrorMsg string      `json:"error_msg"`
	ClientIp string      `json:"client_ip"`
}

var Client *http.Client

func init() {
	// Solve x509: certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	Client = &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
	}
}

func Login(username, password, srunUrl string) {
	challenge := GetChallenge(srunUrl, username)
	ip, acId := GetPortalPage(srunUrl)
	if challenge.ClientIp != ip {
		log.Fatal("Login(): Get different IP from Challenge and Portal Page")
	}
	token := challenge.Challenge

	log.WithField("challenge", token).WithField("ac_id", acId).Debug("Preparation Done")

	q := url.Values{
		"action":   {"login"},
		"username": {username},
		"password": {password},
		"ac_id":    {fmt.Sprint(acId)},
		"ip":       {ip},
		"chksum":   {},
		"info":     {},
		"n":        {"200"},
		"type":     {"1"},
	}

	q.Set("info", GenInfo(q, token))
	q.Set("password", PwdHmd5(password, token))
	q.Set("chksum", Checksum(q, token))

	loginUrl := srunUrl + "/cgi-bin/srun_portal"
	raction := new(RAction)
	GetAndParseJson(loginUrl, q, raction)

	log.Info(raction)
}

func GetChallenge(srunUrl, username string) *Challenge {
	challengeUrl := srunUrl + "/cgi-bin/get_challenge"
	challenge := &Challenge{}

	q := url.Values{}
	q.Add("username", username)
	GetAndParseJson(challengeUrl, q, challenge)

	return challenge
}

func GetAndParseJson(url string, query url.Values, ret interface{}) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	query.Add("callback", "callback")
	req.URL.RawQuery = query.Encode()

	resp, err := Client.Do(req)
	if err != nil {
		log.WithError(err).Fatal("GetAndParseJson(): Failed to Get")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Fatal("GetAndParseJson(): Failed to read body")
	}

	r, _ := regexp.Compile("callback\\((.*)\\)")
	match := r.FindSubmatch(body)[1]

	err = json.Unmarshal(match, ret)
	if err != nil {
		log.WithError(err).Fatal("GetAndParseJson(): Failed to Unmarshal JSON")
	}
	return
}

func GetPortalPage(srunUrl string) (ip, acId string) {
	errHandler := func(err error) {
		if err != nil {
			log.WithError(err).Fatal("GetPortalPage(): Failed")
		}
	}

	resp, _ := Client.Get(srunUrl)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	errHandler(err)

	doc.Find("#user_ip").Each(func(i int, selection *goquery.Selection) {
		if val, ok := selection.Attr("value"); ok {
			ip = val
		}
	})
	doc.Find("#ac_id").Each(func(i int, selection *goquery.Selection) {
		if val, ok := selection.Attr("value"); ok {
			acId = val
		}
	})

	return
}
