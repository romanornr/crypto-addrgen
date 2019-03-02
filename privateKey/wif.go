// Copyright (c) 2019 Romano (Viacoin developer)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package privateKey

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

func NewWIF(net *chaincfg.Params) (*btcec.PrivateKey, error) {
	chaincfg.Register(net)
	secret, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}

	wif, err := btcutil.NewWIF(secret, net, true)
	return wif.PrivKey, err
}

func FromWIF(WIF string) (*btcutil.WIF, error) {
	wif, err := btcutil.DecodeWIF(WIF)
	return wif, err
}

func NewPublicKeyFromWIF(wif btcutil.WIF, net *chaincfg.Params, compressed bool) (*btcutil.AddressPubKey, error) {
	chaincfg.Register(net)
	serializedPubKey := wif.PrivKey.PubKey().SerializeCompressed()
	if !compressed {
		serializedPubKey = wif.PrivKey.PubKey().SerializeUncompressed()
	}
	pk, err := btcutil.NewAddressPubKey(serializedPubKey, net)
	return pk, err
}
