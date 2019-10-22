package ory

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bmizerany/assert"
	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/require"
	"github.com/urfave/negroni"
)

const keys = `{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "33eee3c0-acd7-419d-88f9-cc149ee2238e",
      "n": "uK3ot9aiGrosmArv4-lat59k8TMjZSgpID2TyjyIm3ZRCRKLRXaFtxzZJtzDxo2jOFpyKKMkhgSlYR2bY7s8ijuIFBVJyz54QGdKSLP4tfXlWDauPULYSSgu0vbUUKj1kKjj1TXiWgi82Dp3ZIiKD3ZcGsN7grlM3mvUpUu1x1WBnh20_f8KO9GjxdmaQGheWg-yy0UqcF0G18XrzaLwFNYIaQ1Bz4SelOTgWynIngvx5GcO1PUVKidJ-qlNRYTiyhKRzkJI0qMtvGffLL9TwnIWhYstEPSmhc_P-GSvgFaedaMbjIwmfm0qVAWG9O0qQZlbg0Fmr5DwAYxZNth9-n29uYPnW5qcxssTlpD9g1vlQ0WsRCPVqlyvCnMc8ep_WOVsrwzw25_KNP7OebUflBPJlSgQXH-2N36bejZ_qw2QrvGnYPIxjNid4hBEVFF1W3Rhoi2nRVgi_wQFkZJtQdaIx5JVVF5oZuWbSHrDFj7tcAqzU2ltiHC2xGJIh1c4Ps3WsJ6VP-TzV9GeeCDiCpfe6kR4dQOUQ8wvbvxhyrQxsGV2CPHInVbuZoKs1Sg6kSEALVrsSp-JMPY7oHhtERyi0OFqNjAxIgaFTm5NTKco8aKMF-5OPhNbymphpDwH-o3qsSAxZOPxWjStG3lX6-EEVCEyzzvcRuNW4FAZ4cc"
    }
  ]
}`

// const keys = `{
//   "keys": [
//     {
//       "use": "sig",
//       "kty": "RSA",
//       "kid": "33eee3c0-acd7-419d-88f9-cc149ee2238e",
//       "alg": "RS256",
//       "n": "uK3ot9aiGrosmArv4-lat59k8TMjZSgpID2TyjyIm3ZRCRKLRXaFtxzZJtzDxo2jOFpyKKMkhgSlYR2bY7s8ijuIFBVJyz54QGdKSLP4tfXlWDauPULYSSgu0vbUUKj1kKjj1TXiWgi82Dp3ZIiKD3ZcGsN7grlM3mvUpUu1x1WBnh20_f8KO9GjxdmaQGheWg-yy0UqcF0G18XrzaLwFNYIaQ1Bz4SelOTgWynIngvx5GcO1PUVKidJ-qlNRYTiyhKRzkJI0qMtvGffLL9TwnIWhYstEPSmhc_P-GSvgFaedaMbjIwmfm0qVAWG9O0qQZlbg0Fmr5DwAYxZNth9-n29uYPnW5qcxssTlpD9g1vlQ0WsRCPVqlyvCnMc8ep_WOVsrwzw25_KNP7OebUflBPJlSgQXH-2N36bejZ_qw2QrvGnYPIxjNid4hBEVFF1W3Rhoi2nRVgi_wQFkZJtQdaIx5JVVF5oZuWbSHrDFj7tcAqzU2ltiHC2xGJIh1c4Ps3WsJ6VP-TzV9GeeCDiCpfe6kR4dQOUQ8wvbvxhyrQxsGV2CPHInVbuZoKs1Sg6kSEALVrsSp-JMPY7oHhtERyi0OFqNjAxIgaFTm5NTKco8aKMF-5OPhNbymphpDwH-o3qsSAxZOPxWjStG3lX6-EEVCEyzzvcRuNW4FAZ4cc",
//       "e": "AQAB",
//       "d": "mf9i1JGkwTbH4s0T9u_q1r2SldL3y-1uRdUzPOu3WjOSJUeSXQ0VOXlT1qU2l4YaOe6pzRslZJ_RLCddIQ_LztUPhvetfk6MReAbwH5agZkXcrS-HJV196MLUJ3Es7IAe21p9qulIUCyAHjYgDufLH-dFDA3-Oz9nWc7fc6hOSQjHq9U8oxOg00wDNaEWvrs2prGk9wMJIBeKWWAWQxquGU1xCvq2dmTx0MHlt1Dzg7V2YjahFgOGwWCGgQ9TCAgYTKU5PK--O5bQAU5w32Tocwy3Y8NuFrZ1TFSEaYb9p_EKQInAc8IdlofdsrZG7n8h5ETD2Nk9jec-x2Gc0aZ3O987MXOhC0bBOsojyPl_o3c58HCF5XqEYrq1Dbj90bHCBvzfhhwriXoDuJqhRyrkbvtNpUClhJZMP11d0wC53UsBLqMXZBsHLCh3kYvBqiOW4l1PT8d4yp-O_xI07pKkbSvV5rLrzq0y9zioY8N3YCuSJBIn_V_qXzGMIymyok7qLRONE9jlncSPfUG_ndqvRAsD_UK9fu7zOAiiFCFJ59ryLUJuc50tQEo9KjiMUeIrSlgKOgLK0oeLY1dlBkJi52fiYB1obS0bEKIYc6fLTY5aDk3b2cLtMISAe2Wdmx9IJ6cLe3q9hi_xFu4V987V8VS2Mkp2JswUf0DD4i61Jk",
//       "p": "w5LjXe9eVVsUYXatGJukyZ4ULIZMTe11XI53P_os7qEF9n1dMf-JnLUVXALnZranElJr7-tsXAO8J7J46q8m_XWloVdAM6gfuRuRTUV6mkh20AyU_gOFsuLES8raGQ7RaJVyhpKQQRYjISP6monwwQ6VeYHjfNWN8ihirZJBWamAXZckHyWeAl1a642xpyC-Ct04z09oI_3XigeFEIYak1PgLTesCLXD6GxljRTn8DWbmOxrBCgfYDjFYjI1pwalibS0hXEA1LMd34nI3EaRqklZ2l8OGCC2My25kWrGH9hgXGIvFToi-q0dS-dCxQTGA5RqNT0064cLoJQ6gKU0LQ",
//       "q": "8b1QJX6FmVFojowp6XWaVEIzlmbO-4eINwgmU0ZhOtqfsB9_vo0i2w_3jIc1gH9VkvzlDN-SCeh6Tk1_MDGxQNvp_Hhuq8NagO3CHGHyIzGdV0Y0Betc7uXWDtYP4z7IIC8Tgo1b0EpQA5nBlUGSNwnAs6MNcBxx9tvbKjI5CuSuJWorbvO1-m-NSmbb5BTgZsuH9SwlhjufG7tyt1Mbl2i02DvlHBW0Ztu6-XynLttYDfFki82ceApgFbTIAxSK4RgPMi2iyzEv1u6I7w8yLBD1yoKoYRgs4alMpXPPm3gPjKC4Jc2zpDMmCZy23uQsaledc-6C-cr89fo53PRiQw",
//       "dp": "ezduPF51Jn3Np2InyFs3RTdtKmgqZuZ2jKvNgedSq72TjiqJrth6kNqd7Gx_8fyd4jM_gdbnXEmWH8SX3fQgMowOoEniTylbYzp1HyPpDI8fHBDxReBeOcgZOE9DfYoScTvG_fYVIIyb8WNDnl3N6zQPBJDLDHlXhvvev9Bnj9_02gJBZcZDeOXsRH_vL4a3dQzPn_09dX-WboYyVajH0Y6ErLhokMxD84lnqa1EO9jqgTxiaCoHKo5Z_XX4y5SqcsoA-hmqFlgLOC0M-YsUdx7jl2tP6--gGzpxsaZ90M54V3wcgdkw9JJg5NN9A7fwMY0uJQC8-K8Kqk75VNfAuQ",
//       "dq": "kVlf0DuDvszZDiSuqqXAdnsbo4oLV-eE-nnW-Wku2wFK1M4LtBoOZCL0mDVP8QQfAvM2EYh3uadjqqMkH2kxh6ryxI_xEyuxxiWu-fvWaFzTmv8mFo0O4sGk9GS3Rs6f6-ICXBP8qX-VHqUbZU_4x0kA6cHXOZqQ13oYDAYIkEkxgGOW2-6Dc6IRFTRFcJ0w0_36sGqr4UsF_tm1Pw8kXuRhIEbbGgje4J2rjYjqyNyv1CpZZ0nok7DBVyvMuzVlz7P0pxoTcRMRDa18_ihn5WEJOItZDJBJpCF0aWL56CPHTanxLyHAqrDqZQsqVVhicEpf7K3zaJgpgwjCM91pGw",
//       "qi": "F2ZfqOJ_3D5o--qRL458YGkQlz8wqhbsm2Jxtgixqr6kCwYZOVXrkqrX6Hog2Y1BsRrnN-5x6VyajA45qHbgQBmcYUZn2Jd9UQ2gFZYG9oW7-qp7W591sd0sW9njkPrK8Zf6GwMSY1eoZu_Mk9rT-SqWmVkLZ9seJuY94jK4y951jmCrhV6b6G9k804d_etSkFmg1CS9f4-ZjCmk4bk-sRZkyieDlPyNu8ufNZW0qgBV4n4u9F2gdq4nN8Ai3UCouhPn3DXd0r0wjauX3ZsVFy-tBJ8VqHNHGKZEYP3IOQJc8-smAPiMPM4n3J6KjIfA1Jaj7v0NHOrGeXXdJCajJA"
//     }
//   ]
// }`

func TestSessionFromRequest(t *testing.T) {
	ks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(keys))
	}))
	defer ks.Close()

	router := httprouter.New()
	router.GET("/me", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		s, err := SessionFromRequest(r)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(s))
	})
	n := negroni.New()
	n.Use(NewMiddleware(ks.URL).NegroniHandler())
	n.UseHandler(router)

	ts := httptest.NewServer(n)
	defer ts.Close()

	for k, tc := range []struct {
		token              string
		expectedStatusCode int
		expectedResponse   string
	}{
		// token without token
		{
			token:              "",
			expectedStatusCode: 401,
			expectedResponse:   "Authorization header format must be Bearer {token}",
		},
		// token without kid
		{
			token:              "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjo5OTk5OTk5OTk5LCJzZXNzaW9uIjp7ImlkZW50aXR5Ijp7ImlkIjoiMTIzNDU2Nzg5MCJ9fX0.j0SgjC21nhkNP2QX0uE-I4wDYYRYlZq9wqGeDhrbplkKGW4BOjW5Sk0XFFbqrx68hQYz23QvYOYW5avUBzTjPxHwVqB1HPv6M5P2wHvRn7ZvAyhz83fmJMnBRNBOz1MfjxnEgkwfcVbNqsW2y37kRdZfveBlAzSfuPJV8Rkb4wlBbEGUwoCk78j8zcD_dcYFfXbt7uXz_tscScoIOg959Rmwr2E1XqRNy2qWLKSImwo8athdEEE-byLYytg6mgM02bmEQk2dyd5W2MmqG_4UaiBru6Bf9-drqExHDGUyndnAKi_uvF_131_LkPxy6H5Hu_YfZgSE5hXUbRsBzU-gbY5aV5FSn855PnRDyS_lFnBEn-0vcCIMmxbdfhqyKtFPmFHdSO1YsGruhqYaOLOlTVzThP-1XJSpgMKXHXW35c52zB9AaTV-0ETICvZ_OjZM_uzdWeb6PQmFsztcwdO-9C70yR3_HdcjljvnQ4XHs9ho_3_V57fcbW3uQCTq0TRbwD0AXpkVOvKJqaP1yEXYLKSNpGL2MMkuY-i3k6wTZMTV1280TqbJcSpY5n6WoWJnjoZ08BwBQDfX8AUsKk-D71wJbONqmLo5YnmrS-1gHR3bKCfuUzDdvensLXYJwSHg3ae_qE5VxscRhT_p2odeE8JgQBhd0d6765YBAP93F1c",
			expectedStatusCode: 401,
			expectedResponse:   "jwt from authorization HTTP header is missing value for \"kid\" in token header",
		},
		// token with int kid
		{
			token:              "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MTIzfQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjo5OTk5OTk5OTk5LCJzZXNzaW9uIjp7ImlkZW50aXR5Ijp7ImlkIjoiMTIzNDU2Nzg5MCJ9fX0.pG51ns8s_HeRC_KwtO7SNtIinqgVlSketJs7EjrHbW1xHvLRwCl4qhtIRuLqlED6eTEnqS2r2f6OFAiOJIZl9I6mQttSraHNcUOvK6t0bYg9w_K0HcaVu_894uJLZBTMx0B8mbqr7rZoRN_frriGkkjXbMP75-g1crA-t7_0VQeGwRPx0bcSF0T5yFRQyRlRwUTb6NbpLp6mc6NxMRP5OZPqnMTXAtP9YOfGLFdmhZ5CK1GUTdCRicwUyUOre8MNm4uIPZTTBZav06ncvjK80ATX7hkJqQfvvSlTee0LsLNHpuKPMCb_jmDaEugMXzvKPZ40L-r93KJ0TlK_dqu75imiK5aVuPaz8mk3cno4_0PW3ia0z5e00dWla1E8X1bOiW-4XvNdD1GGYGG0oBje67FnNFYQU2ApECbFN-3yGraneZFEcWWsf3CAEukcrmjjJLXYX0koUBtqvClOXHpKvwu-WhZ4eFYPoJoEysS4WeX7onxls2YdHsMBG9Ku-F26qzIHi1pDNsGb3eDbsGAMjaqEV81YfzwgBIF1nhfzuS0IU3LMoiwbwyQA6-hsAcV1dHTIoIW4VT1iEk90fsLzEMprh__SxYFIlOXchDWPD08sHLQk2kVLUR_BosdrygmTwkHVsq_lvIH77FsDkhwdKpD_sgdIdW_ttnYtCdMGlJc",
			expectedStatusCode: 401,
			expectedResponse:   "jwt from authorization HTTP header is expecting string value for \"kid\" in tokenWithoutKid header but got: float64",
		},
		// token with unknown kid
		{
			token:              "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im5vdC1hLXZhbGlkLWtpZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjo5OTk5OTk5OTk5LCJzZXNzaW9uIjp7ImlkZW50aXR5Ijp7ImlkIjoiMTIzNDU2Nzg5MCJ9fX0.rX173fvU_Ed2p-iYF8PcRr4tS4e-BZR8RFV_CVtgEJxk2vMZHOlygJgvTZVK1cIP63EpHVqK_Sr5b1ctapLxpWMoxXBfdnyegZ5gLrDZ5vnbTJoWxpPo71D2RK2dC9qLwjBQr0MlYaLFUZrPcPOhsoYMlPTzLXamR0EGTY8lzPJhi3FubbnIWmq91v1ie-kF5d2Mxw_VnvF7ZJB5JwIH2KxkyVmGtImydmmkiXfuiNx1jejM68XW3mtfOFcuJYxc01jYR3l1Jh4E09hXNjYxqrR6oUjbmQZum60AInR_UyXw2myjkeAxj-m89ndm_z2MjrT0Za0cBuz0hY45FX6lOuANCCN6KOK3WmgdR6MCLxDWkNauicpMvsj14vF7V6W9kMpROE3YGxYySdG0ob8dtOurbYbFewFGi_ivmq7boMgwE1u6KpIKpW_DOjxCPcyP9UpxyAtFOGzV9cDUY_VA6rRWYktfBzE2HQpMPxX41FVhUT8Up0FGoUe1xnPkHLza17ZsGDVbfOMC-ji_kPRNi6rCZSn_nidr_7NbwhhaYkuPdWYtPLhr0XTsuwC2U0yGduwzP-ew8GiHQUvNBdio_WxhSHZm5WerFWzMB2_3QiMkh9O77axz1BmDGyXxs1OzUlvUKtPBlAz5b8oH_wdbGHiDfpL4c4qL_QAZfFpma4I",
			expectedStatusCode: 401,
			expectedResponse:   "unable to find JSON Web Key with ID: not-a-valid-kid",
		},
		// token with valid kid
		{
			token:              "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjMzZWVlM2MwLWFjZDctNDE5ZC04OGY5LWNjMTQ5ZWUyMjM4ZSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjo5OTk5OTk5OTk5LCJpZGVudGl0eSI6eyJpZCI6IjEyMzQ1Njc4OTAifX0.kHRbe0iBnDDpkCXH3e5-biRXStQIhWTN79yoVX5ijekZctHme12F8JTifY_lWKEWShVbO2qn_KrMV9CZX6dFwXEl84SjRa3LeizS50v6ZcpmhkymahTrONhs0MmsXdpS6zNH4t4t3wjIQ5HrJoUE2QoMDGHxnbI3dhr_CE66uqCdt5Prm4tbMfuXXZ1E9FfZl6_mQpzgH_YQx0SbjggmqE3UXDmeeYkuXZJ_srWRQnuUlIHU1A9uhWgLM2vH6lFV3wdzQpqAvNP1tkNNUOh4oZAfK1cG5W64omYkurHoQllF8dAPylhbIlfe2yAepEnfY3sBIs0uWrOcahfz20Apbkzg7ciOs52vDiDnsgJiiLjxLfP6FPGeysUkTdCiEsS8boUjUiudglFAmkYqKCdcZSp7QIg__1ZX4SlDO9vYZgdHuF1tsAmviBmNGK7A78LULogNIuDaJAQR-kbdvAwX5u08yZ8DR-cY2Sfb7U_bF4UF_kmDPSOfdw6iNg3qRVUinhSmDvr5u1GWXMCG4aZtSB_KfIbrIfokzdb_5AE7FuTAtMb5XOtwnYXlJciiJwE3zsp4inaEcKaf9MOQiwVQbt4ghhekE-KZPLgkq6MFVmCC7_WMWZPSraHiQxN3HlUO-afTtYezbZAhN_rSX9jfEAQ2wVOIsdCpsSqkA0U3Md8",
			expectedStatusCode: 200,
			expectedResponse:   "{\"identity\":{\"id\":\"1234567890\"}}",
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			req, err := http.NewRequest("GET", ts.URL+"/me", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "bearer "+tc.token)
			require.NoError(t, err)

			res, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer res.Body.Close()

			body, err := ioutil.ReadAll(res.Body)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedStatusCode, res.StatusCode, string(body))
			assert.Equal(t, tc.expectedResponse, strings.TrimSpace(string(body)))
		})
	}
}
