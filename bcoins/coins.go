// Copyright (c) 2019 Romano (Viacoin developer)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package bcoins

import (
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"strings"
)

type Coin struct {
	Name          string
	Unit          string
	Symbol        string
	Network       *Network
}

type Network struct {
	Name            string
	P2PKH           byte
	P2SH            byte
	PrivateKeyID    byte
	HDCoinType      uint32
	HDPrivateKeyID  [4]byte
	HDPublicKeyID   [4]byte
	magic           wire.BitcoinNet
	Bech32HRPSegwit string
}

var coins = map[string]Coin{
	"via": {
		Name: "viacoin", Symbol: "via", Unit: "VIA",
		Network: &Network{
			Name:            "viacoin",
			P2PKH:           0x47,
			P2SH:            0x21,
			PrivateKeyID:    0xC7,
			HDCoinType:      14,
			magic:           0xcbc6680f,
			Bech32HRPSegwit: "via",
		},
	},

	"ltc": {
		Name: "litecoin", Symbol: "ltc", Unit: "LTC",
		Network: &Network{
			Name:            "litecoin",
			P2PKH:           0x30,
			P2SH:            0x32,
			PrivateKeyID:    0xB0,
			HDCoinType:      2,
			HDPrivateKeyID:  [4]byte{0x04, 0x88, 0xad, 0xe4},
			HDPublicKeyID:   [4]byte{0x04, 0x88, 0xb2, 0x1e},
			magic:           0xfbc0b6db,
			Bech32HRPSegwit: "ltc",
		},
	},
}

// select a coin by symbol and return Coin struct and error
// coin symbol to lower case
func SelectCoin(symbol string) (Coin, error) {
	if coins, ok := coins[strings.ToLower(symbol)]; ok {
		return coins, nil
	}
	return Coin{}, fmt.Errorf("altcoin %s not found\n", symbol)
}

// set the chainparams correct for the given Network struct
// and returns the chaincfg.Params
func (network Network) ChainCgfMainNetParams() *chaincfg.Params {
	networkParams := &chaincfg.MainNetParams
	networkParams.Name = network.Name
	networkParams.Net = network.magic
	networkParams.PubKeyHashAddrID = network.P2PKH
	networkParams.ScriptHashAddrID = network.P2SH
	networkParams.HDCoinType = network.HDCoinType
	networkParams.HDPrivateKeyID = network.HDPrivateKeyID
	networkParams.HDPublicKeyID = network.HDPublicKeyID
	networkParams.PrivateKeyID = network.PrivateKeyID
	networkParams.Bech32HRPSegwit = network.Bech32HRPSegwit
	return networkParams
}
