// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package codefresh

import (
	//"bytes"
	"context"
	//"crypto/x509"
	//"encoding/asn1"
	"encoding/json"
	//"errors"
	//"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	//"github.com/sigstore/fulcio/pkg/identity"
)

func TestJobPrincipalFromIDToken(t *testing.T) {
	tests := map[string]struct {
		Claims          map[string]interface{}
		ExpectPrincipal workflowPrincipal
		WantErr         bool
		ErrContains     string
	}{
		`Valid token - Manual trigger authenticates with correct claims`: {
			Claims: map[string]interface{}{
				"sub": "account:628a80b693a15c0f9c13ab75:pipeline:65e5a53e52853dc51a5b0cc1:initiator:codefresh-user",
				"account_id": "628a80b693a15c0f9c13ab75",
				"account_name": "codefresh-account",
				"pipeline_id": "65e5a53e52853dc51a5b0cc1",
				"pipeline_name": "oidc-test/get-token",
				"workflow_id": "65e5c23d706f166c4e8985ed",
				"initiator": "codefresh-user",
				"runner_environment": "hybrid",
				"aud": "sigstore",
				"exp": 1709556619,
				"iat": 1709556319,
				"iss": "https://oidc.codefresh.io",
				"platform_url": "https://pre-prod.codefresh.io",
			},
			ExpectPrincipal: workflowPrincipal{
				issuer:  "https://oidc.codefresh.io",
				subject: "account:628a80b693a15c0f9c13ab75:pipeline:65e5a53e52853dc51a5b0cc1:initiator:codefresh-user",
				accountID: "628a80b693a15c0f9c13ab75",
				accountName: "codefresh-account",
				pipelineID: "65e5a53e52853dc51a5b0cc1",
				pipelineName: "oidc-test/get-token",
				workflowID: "65e5c23d706f166c4e8985ed",
				initiator: "codefresh-user",
				platformURL: "https://pre-prod.codefresh.io",
				runnerEnvironment: "hybrid",
			},
			WantErr: false,
		},
		`Valid token - Git push trigger authenticates with correct claims`: {
			Claims: map[string]interface{}{
				"sub": "account:628a80b693a15c0f9c13ab75:pipeline:65e5a53e52853dc51a5b0cc1:initiator:codefresh-user:scm_repo_url:https://github.com/codefresh-user/fulcio:scm_user_name:git-user-name:scm_ref:main",
				"account_id": "628a80b693a15c0f9c13ab75",
				"account_name": "codefresh-account",
				"pipeline_id": "65e5a53e52853dc51a5b0cc1",
				"pipeline_name": "oidc-test/get-token",
				"workflow_id": "65e6bcf7c2af1f228fa97f80",
				"initiator": "codefresh-user",
				"scm_user_name": "git-user-name",
				"scm_repo_url": "https://github.com/codefresh-io/fulcio-oidc",
				"scm_ref": "main",
				"runner_environment": "hybrid",
				"aud": "sigstore",
				"exp": 1709620814,
				"iat": 1709620514,
				"iss": "https://oidc.codefresh.io",
			},
			ExpectPrincipal: workflowPrincipal{
				issuer:  "https://oidc.codefresh.io",
				subject: "account:628a80b693a15c0f9c13ab75:pipeline:65e5a53e52853dc51a5b0cc1:initiator:codefresh-user:scm_repo_url:https://github.com/codefresh-user/fulcio:scm_user_name:git-user-name:scm_ref:main",
				accountID: "628a80b693a15c0f9c13ab75",
				accountName: "codefresh-account",
				pipelineID: "65e5a53e52853dc51a5b0cc1",
				pipelineName: "oidc-test/get-token",
				workflowID: "65e6bcf7c2af1f228fa97f80",
				initiator: "codefresh-user",
				scmUsername: "git-user-name",
				scmRepoUrl: "https://github.com/codefresh-io/fulcio-oidc",
				scmRef: "main",
				platformURL: "https://g.codefresh.io",
				runnerEnvironment: "hybrid",
			},
			WantErr: false,
		},
		`Token missing workflow_id claim should be rejected`: {
			Claims: map[string]interface{}{
				"sub": "account:628a80b693a15c0f9c13ab75:pipeline:65e5a53e52853dc51a5b0cc1:initiator:codefresh-user",
				"account_id": "628a80b693a15c0f9c13ab75",
				"account_name": "codefresh-oidc",
				"pipeline_id": "65e5a53e52853dc51a5b0cc1",
				"pipeline_name": "oidc-test/get-token",
				"initiator": "codefresh-user",
				"aud": "sigstore",
				"exp": 1709556619,
				"iat": 1709556319,
				"iss": "https://oidc.codefresh.io",
			},
			WantErr:     true,
			ErrContains: "workflow_id",
		},
		`Token missing account_id claim should be rejected`: {
			Claims: map[string]interface{}{
				"sub": "account:628a80b693a15c0f9c13ab75:pipeline:65e5a53e52853dc51a5b0cc1:initiator:codefresh-user",
				"account_name": "codefresh-oidc",
				"pipeline_id": "65e5a53e52853dc51a5b0cc1",
				"pipeline_name": "oidc-test/get-token",
				"initiator": "codefresh-user",
				"aud": "sigstore",
				"exp": 1709556619,
				"iat": 1709556319,
				"iss": "https://oidc.codefresh.io",
			},
			WantErr:     true,
			ErrContains: "account_id",
		},
		`Token missing pipeline_id claim should be rejected`: {
			Claims: map[string]interface{}{
				"sub": "account:628a80b693a15c0f9c13ab75:pipeline:65e5a53e52853dc51a5b0cc1:initiator:codefresh-user",
				"account_name": "codefresh-oidc",
				"account_id": "628a80b693a15c0f9c13ab75",
				"pipeline_name": "oidc-test/get-token",
				"workflow_id": "65e6bcf7c2af1f228fa97f80",
				"initiator": "codefresh-user",
				"aud": "sigstore",
				"exp": 1709556619,
				"iat": 1709556319,
				"iss": "https://oidc.codefresh.io",
			},
			WantErr:     true,
			ErrContains: "pipeline_id",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			token := &oidc.IDToken{
				Issuer:  test.Claims["iss"].(string),
				Subject: test.Claims["sub"].(string),
			}
			claims, err := json.Marshal(test.Claims)
			if err != nil {
				t.Fatal(err)
			}
			withClaims(token, claims)

			untyped, err := WorkflowPrincipalFromIDToken(context.TODO(), token)
			if err != nil {
				if !test.WantErr {
					t.Fatal("didn't expect error", err)
				}
				if !strings.Contains(err.Error(), test.ErrContains) {
					t.Fatalf("expected error %s to contain %s", err, test.ErrContains)
				}
				return
			}
			if err == nil && test.WantErr {
				t.Fatal("expected error but got none")
			}

			principal, ok := untyped.(*workflowPrincipal)
			if !ok {
				t.Errorf("Got wrong principal type %v", untyped)
			}
			if *principal != test.ExpectPrincipal {
				t.Errorf("got %v principal and expected %v", *principal, test.ExpectPrincipal)
			}
		})
	}
}

// reflect hack because "claims" field is unexported by oidc IDToken
// https://github.com/coreos/go-oidc/pull/329
func withClaims(token *oidc.IDToken, data []byte) {
	val := reflect.Indirect(reflect.ValueOf(token))
	member := val.FieldByName("claims")
	pointer := unsafe.Pointer(member.UnsafeAddr())
	realPointer := (*[]byte)(pointer)
	*realPointer = data
}