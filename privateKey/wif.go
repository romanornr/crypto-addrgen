// Copyright (c) 2019 Romano (Viacoin developer)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package privateKey

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
)

func NewWIF(net *chaincfg.Params) (*btcutil.WIF, error) {
	chaincfg.Register(net)
	secret, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}

	wif, err := btcutil.NewWIF(secret, net, true)
	return wif, err
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

func WIFToSegwit(wif *btcutil.WIF, net *chaincfg.Params) (*btcutil.AddressScriptHash, error) {
	keyHash := btcutil.Hash160(wif.SerializePubKey())
	scriptSig, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(keyHash).Script()
	if err != nil {
		panic(err)
	}
	segwitAddress, err := btcutil.NewAddressScriptHash(scriptSig, net)
	if err != nil {
		panic(err)
	}

	return segwitAddress, err
}

//func Reee(net *chaincfg.Params) {
//	acct0Pub, err := hdkeychain.NewKeyFromString("xpub6Cb8Q6pDeS8PdKNbDv9Hvq4WpJXL3JvKvmHHwR1wD2H543hiCUE1f1tB5AXE6yg13k7xZ6PzEXMNUFHXk6kkx4RYte8VB1i4tCX9rwQVR4a")
//	if err != nil {
//		panic(err)
//	}
//
//	// m/49'/1'/0'/0
//	acct0ExternalPub, err := acct0Pub.Child(0)
//	if err != nil {
//		panic(err)
//	}
//
//	// m/49'/1'/0'/0/0
//	acct0External0Pub, err := acct0ExternalPub.Child(0)
//	if err != nil {
//		panic(err)
//	}
//
//	// BIP49 segwit pay-to-script-hash style address.
//	pubKey, err := acct0External0Pub.ECPubKey()
//	if err != nil {
//		panic(err)
//	}
//	keyHash := btcutil.Hash160(pubKey.SerializeCompressed())
//	scriptSig, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(keyHash).Script()
//	if err != nil {
//		panic(err)
//	}
//	acct0ExtAddr0, err := btcutil.NewAddressScriptHash(scriptSig, net)
//	if err != nil {
//		panic(err)
//	}
//	fmt.Println(acct0ExtAddr0)
//}
