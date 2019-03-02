// Copyright (c) 2019 Romano (Viacoin developer)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package bcoins

import "testing"

func TestSelectCoin(t *testing.T) {
	var tests = []struct {
		assetSymbol string
		Name        string
	}{
		{"via", "viacoin"},
		{"ltc", "litecoin"},
	}

	for _, test := range tests {
		asset, err := SelectCoin(test.assetSymbol)
		if err != nil {
			t.Errorf("Test failed: %s", err)
		}

		if asset.Name != test.Name {
			t.Error(
				"For", test.Name,
				"expected", test.Name,
				"got", asset.Name,
			)
		}
	}
}
