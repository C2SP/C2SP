package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"text/template"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v69/github"
)

type TeamMember struct {
	Login     string `json:"login"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
}

const c2spGitHubAppID = 1185968
const c2spGitHubInstallationID = 63003777

func main() {
	tr, err := ghinstallation.New(
		http.DefaultTransport,
		c2spGitHubAppID, c2spGitHubInstallationID,
		[]byte(os.Getenv("GITHUB_APP_PRIVATE_KEY")),
	)
	if err != nil {
		log.Fatalf("Failed to create GitHub App transport: %v", err)
	}

	githubClient := github.NewClient(&http.Client{Transport: tr})

	http.HandleFunc("GET /team/{slug}", func(w http.ResponseWriter, r *http.Request) {
		teamSlug := r.PathValue("slug")
		if teamSlug == "" {
			http.Error(w, "Missing team slug", http.StatusBadRequest)
			return
		}

		members, _, err := githubClient.Teams.ListTeamMembersBySlug(
			r.Context(),
			"C2SP", teamSlug,
			&github.TeamListTeamMembersOptions{},
		)
		if err != nil {
			log.Printf("Error fetching team members: %v", err)
			http.Error(w, fmt.Sprintf("Failed to fetch team members: %v", err), http.StatusInternalServerError)
			return
		}

		teamMembers := make([]TeamMember, 0, len(members))
		for _, member := range members {
			teamMembers = append(teamMembers, TeamMember{
				Login:     member.GetLogin(),
				AvatarURL: member.GetAvatarURL(),
				HTMLURL:   member.GetHTMLURL(),
			})
		}

		slices.SortFunc(teamMembers, func(a, b TeamMember) int {
			return strings.Compare(a.Login, b.Login)
		})

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		err = tmpl.Execute(w, struct {
			TeamSlug string
			Members  []TeamMember
		}{
			TeamSlug: teamSlug,
			Members:  teamMembers,
		})
		if err != nil {
			log.Printf("Error rendering HTML template: %v", err)
			http.Error(w, "Error rendering response", http.StatusInternalServerError)
			return
		}
	})

	log.Printf("Starting server on %s", ":8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

var tmpl = template.Must(template.New("teamMembers").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>@C2SP/{{.TeamSlug}} members</title>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
			line-height: 1.6;
			color: #333;
			max-width: 1000px;
			margin: 0 auto;
			padding: 20px;
		}
		h1 {
			color: #24292e;
		}
		table {
            width: auto;
            max-width: 500px;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            padding: 0 20px;
        }
        th, td {
            padding: 12px 25px;
            text-align: left;
            border-bottom: 1px solid #e1e4e8;
        }
		th {
			background-color: #f6f8fa;
			font-weight: 600;
		}
		tr:hover {
			background-color: #f6f8fa;
		}
		img.avatar {
			width: 40px;
			height: 40px;
			border-radius: 50%;
			vertical-align: middle;
			margin-right: 10px;
		}
		.member-cell {
			display: flex;
			align-items: center;
		}
		a {
			color: #0366d6;
			text-decoration: none;
		}
		a:hover {
			text-decoration: underline;
		}
	</style>
</head>
<body>
	<h1>@C2SP/{{.TeamSlug}} members</h1>
	<table>
		<tbody>
			{{range .Members}}
			<tr>
				<td class="member-cell">
					<img src="{{.AvatarURL}}" class="avatar" alt="{{.Login}}'s avatar">
					<a href="{{.HTMLURL}}" target="_blank">{{.Login}}</a>
				</td>
			</tr>
			{{end}}
		</tbody>
	</table>
</body>
</html>
`))
