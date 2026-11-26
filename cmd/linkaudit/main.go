package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"dvpn-sim/internal/link"
)

type relayArg struct {
	id  string
	url string
}

type halfAt struct {
	url  string
	half link.Half
}

func getJSON(url string, v any) error {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func main() {
	relaysFlag := flag.String("relays", "", "comma-separated id=control-url list")
	minChallenges := flag.Int("challenges", 3, "max challenge packets per link")
	flag.Parse()
	if *relaysFlag == "" {
		fmt.Fprintln(os.Stderr, "-relays is required")
		os.Exit(2)
	}

	var relays []relayArg
	for _, part := range strings.Split(*relaysFlag, ",") {
		id, url, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || id == "" || url == "" {
			fmt.Fprintf(os.Stderr, "bad relay %q\n", part)
			os.Exit(2)
		}
		relays = append(relays, relayArg{id: id, url: strings.TrimRight(url, "/")})
	}

	byTag := map[string][]halfAt{}
	for _, r := range relays {
		var halves []link.Half
		if err := getJSON(r.url+"/links", &halves); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", r.id, err)
			os.Exit(1)
		}
		for _, h := range halves {
			byTag[h.Tag] = append(byTag[h.Tag], halfAt{url: r.url, half: h})
		}
	}

	links, okLinks, failed := 0, 0, 0
	challenges, okChallenges := 0, 0
	for tag, hs := range byTag {
		var sender, receiver *halfAt
		for i := range hs {
			switch hs[i].half.Role {
			case "sender":
				sender = &hs[i]
			case "receiver":
				receiver = &hs[i]
			}
		}
		if sender == nil || receiver == nil {
			continue
		}
		links++
		if !link.VerifyHalf(sender.half) || !link.VerifyHalf(receiver.half) {
			fmt.Printf("FAIL tag=%s bad signature\n", tag)
			failed++
			continue
		}
		if sender.half.To != receiver.half.To {
			fmt.Printf("FAIL tag=%s to mismatch sender=%s receiver=%s\n", tag, sender.half.To, receiver.half.To)
			failed++
			continue
		}
		if sender.half.Packets != receiver.half.Packets || sender.half.Bytes != receiver.half.Bytes {
			fmt.Printf("FAIL tag=%s count mismatch sent=%d/%d recv=%d/%d\n", tag,
				sender.half.Packets, sender.half.Bytes, receiver.half.Packets, receiver.half.Bytes)
			failed++
			continue
		}
		okLinks++

		if sender.half.Packets == 0 {
			continue
		}
		seqs := []int{1, int(sender.half.Packets / 2), int(sender.half.Packets)}
		seen := map[int]bool{}
		nCh := 0
		for _, seq := range seqs {
			if seq < 1 || seen[seq] || nCh >= *minChallenges {
				continue
			}
			seen[seq] = true
			nCh++
			sp, spErr := fetchProof(sender.url, tag, seq)
			rp, rpErr := fetchProof(receiver.url, tag, seq)
			challenges++
			if spErr != nil || rpErr != nil {
				fmt.Printf("FAIL tag=%s seq=%d proof fetch: %v / %v\n", tag, seq, spErr, rpErr)
				continue
			}
			if !link.VerifyHash(sp) || !link.VerifyHash(rp) || sp.Hash != rp.Hash {
				fmt.Printf("FAIL tag=%s seq=%d hash mismatch\n", tag, seq)
				continue
			}
			okChallenges++
		}
	}

	fmt.Printf("linkaudit links=%d ok=%d failed=%d challenges=%d ok_challenges=%d\n",
		links, okLinks, failed, challenges, okChallenges)
	if failed > 0 || okLinks == 0 || okChallenges == 0 {
		os.Exit(1)
	}
}

func fetchProof(url, tag string, seq int) (link.HashProof, error) {
	var p link.HashProof
	err := getJSON(fmt.Sprintf("%s/hash?tag=%s&seq=%d", url, tag, seq), &p)
	return p, err
}
