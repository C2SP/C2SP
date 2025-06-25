package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/google/go-github/v73/github"
)

type TeamInfo struct {
	Name    string
	Members []string
}

func main() {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatalf("GITHUB_TOKEN environment variable is required")
	}

	githubClient := github.NewClient(nil).WithAuthToken(token)
	ctx := context.Background()

	// Get stewards team
	stewards, err := getTeamInfo(ctx, githubClient, "stewards")
	if err != nil {
		log.Fatalf("Failed to get stewards team: %v", err)
	}

	// Get maintainers parent team to find its child teams
	maintainersTeam, _, err := githubClient.Teams.GetTeamBySlug(ctx, "C2SP", "maintainers")
	if err != nil {
		log.Fatalf("Failed to get maintainers team: %v", err)
	}

	// Get all teams and filter for child teams of maintainers
	allTeams, _, err := githubClient.Teams.ListTeams(ctx, "C2SP", &github.ListOptions{})
	if err != nil {
		log.Fatalf("Failed to list teams: %v", err)
	}

	var childTeams []*github.Team
	for _, team := range allTeams {
		if team.Parent != nil && team.Parent.GetID() == maintainersTeam.GetID() {
			childTeams = append(childTeams, team)
		}
	}

	var maintainerTeams []TeamInfo
	for _, team := range childTeams {
		teamSlug := team.GetSlug()
		teamInfo, err := getTeamInfo(ctx, githubClient, teamSlug)
		if err != nil {
			log.Printf("Warning: Failed to get members for team %s: %v", teamSlug, err)
			continue
		}
		maintainerTeams = append(maintainerTeams, teamInfo)
	}

	// Sort maintainer teams by name
	slices.SortFunc(maintainerTeams, func(a, b TeamInfo) int {
		return strings.Compare(a.Name, b.Name)
	})

	// Generate MAINTAINERS.md content
	var content strings.Builder

	// Add stewards section
	if len(stewards.Members) > 0 {
		content.WriteString("## Stewards\n\n")
		for _, member := range stewards.Members {
			content.WriteString(fmt.Sprintf("- [@%s](https://github.com/%s)\n", member, member))
		}
		content.WriteString("\n")
	}

	// Add maintainer teams section
	if len(maintainerTeams) > 0 {
		content.WriteString("## Specification Maintainers\n\n")
		for _, team := range maintainerTeams {
			content.WriteString(fmt.Sprintf("### %s\n\n", team.Name))
			for _, member := range team.Members {
				content.WriteString(fmt.Sprintf("- [@%s](https://github.com/%s)\n", member, member))
			}
			content.WriteString("\n")
		}
	}

	// Write the file
	outputPath := "../MAINTAINERS.md"
	err = os.WriteFile(outputPath, []byte(content.String()), 0644)
	if err != nil {
		log.Fatalf("Failed to write MAINTAINERS.md: %v", err)
	}

	log.Printf("Successfully updated %s", outputPath)
}

func getTeamInfo(ctx context.Context, client *github.Client, teamSlug string) (TeamInfo, error) {
	members, _, err := client.Teams.ListTeamMembersBySlug(
		ctx, "C2SP", teamSlug, &github.TeamListTeamMembersOptions{},
	)
	if err != nil {
		return TeamInfo{}, err
	}

	var memberLogins []string
	for _, member := range members {
		memberLogins = append(memberLogins, member.GetLogin())
	}
	slices.Sort(memberLogins)

	return TeamInfo{
		Name:    teamSlug,
		Members: memberLogins,
	}, nil
}
