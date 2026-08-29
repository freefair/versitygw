// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package s3api

import (
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
)

func TestS3ApiRouter_Init(t *testing.T) {
	tests := []struct {
		name string
		sa   *S3ApiRouter
	}{
		{
			name: "Initialize S3 api router",
			sa: &S3ApiRouter{
				app: fiber.New(),
				be:  backend.BackendUnsupported{},
				iam: &auth.IAMServiceInternal{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.sa.Init()
		})
	}
}

func TestBucketConfigurationRoutesVerifyChecksums(t *testing.T) {
	source, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"encryption", "lifecycle"} {
		start := strings.Index(string(source), `middlewares.MatchQueryArgs("`+query+`")`)
		if start < 0 {
			t.Fatalf("route for %s not found", query)
		}
		end := strings.Index(string(source[start:]), "\n\tbucketRouter.Put(")
		if end < 0 {
			end = len(source) - start
		}
		route := string(source[start : start+end])
		if !strings.Contains(route, "middlewares.VerifyChecksums(false, false, false)") {
			t.Fatalf("%s route does not verify request checksums", query)
		}
	}
}
