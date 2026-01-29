package providers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

const (
	gitlabProviderName  = "GitLab"
	gitlabDefaultScope  = "openid email"
	gitlabProjectPrefix = "project:"
)

// GitLabProvider 代表基于 GitLab 的身份提供者。
type GitLabProvider struct {
	*OIDCProvider

	allowedProjects []*gitlabProject
	// Expose this for unit testing
	oidcRefreshFunc func(context.Context, *sessions.SessionState) (bool, error)
}

var _ Provider = (*GitLabProvider)(nil)

// NewGitLabProvider 初始化一个新的 GitLabProvider。
func NewGitLabProvider(p *ProviderData, opts options.Provider) (*GitLabProvider, error) {
	p.setProviderDefaults(providerDefaults{
		name: gitlabProviderName,
	})

	if p.Scope == "" {
		p.Scope = gitlabDefaultScope
	}

	oidcProvider := NewOIDCProvider(p, opts.OIDCConfig)

	provider := &GitLabProvider{
		OIDCProvider:    oidcProvider,
		oidcRefreshFunc: oidcProvider.RefreshSession,
	}
	provider.setAllowedGroups(opts.GitLabConfig.Group)

	if err := provider.setAllowedProjects(opts.GitLabConfig.Projects); err != nil {
		return nil, fmt.Errorf("could not configure allowed projects: %v", err)
	}

	return provider, nil
}

// setAllowedProjects 将 GitLab 项目添加到 AllowedGroups 列表，并跟踪它们以便在 EnrichSession 期间进行项目 API 查找。
func (p *GitLabProvider) setAllowedProjects(projects []string) error {
	for _, project := range projects {
		gp, err := newGitlabProject(project)
		if err != nil {
			return err
		}
		p.allowedProjects = append(p.allowedProjects, gp)
		p.AllowedGroups[formatProject(gp)] = struct{}{}
	}
	if len(p.allowedProjects) > 0 {
		p.setProjectScope()
	}
	return nil
}

// gitlabProject 代表一个 GitLab 项目约束实体。
type gitlabProject struct {
	Name        string
	AccessLevel int
}

// newGitlabProject 从格式为 `namespace/project=accesslevel` 的项目字符串创建一个新的 gitlabProject 结构。
// 如果未提供访问级别，则使用默认值。
func newGitlabProject(project string) (*gitlabProject, error) {
	const defaultAccessLevel = 20
	// see https://docs.gitlab.com/ee/api/members.html#valid-access-levels
	validAccessLevel := [4]int{10, 20, 30, 40}

	parts := strings.SplitN(project, "=", 2)
	if len(parts) == 2 {
		lvl, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}
		for _, valid := range validAccessLevel {
			if lvl == valid {
				return &gitlabProject{
					Name:        parts[0],
					AccessLevel: lvl,
				}, nil
			}
		}
		return nil, fmt.Errorf("invalid gitlab project access level specified (%s)", parts[0])
	}

	return &gitlabProject{
		Name:        project,
		AccessLevel: defaultAccessLevel,
	}, nil
}

// setProjectScope 确保在按项目过滤时将 read_api 添加到 scope。
func (p *GitLabProvider) setProjectScope() {
	for _, val := range strings.Split(p.Scope, " ") {
		if val == "read_api" {
			return
		}
	}
	p.Scope += " read_api"
}

// EnrichSession 使用来自 userinfo API 端点和允许项目的 projects API 端点的响应丰富会话。
func (p *GitLabProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Retrieve user info
	userinfo, err := p.getUserinfo(ctx, s)
	if err != nil {
		return fmt.Errorf("failed to retrieve user info: %v", err)
	}

	// Check if email is verified
	if !p.AllowUnverifiedEmail && !userinfo.EmailVerified {
		return fmt.Errorf("user email is not verified")
	}

	if userinfo.Nickname != "" {
		s.User = userinfo.Nickname
	}
	if userinfo.Email != "" {
		s.Email = userinfo.Email
	}
	if len(userinfo.Groups) > 0 {
		s.Groups = userinfo.Groups
	}

	// Add projects as `project:blah` to s.Groups
	p.addProjectsToSession(ctx, s)

	return nil
}

type gitlabUserinfo struct {
	Nickname      string   `json:"nickname"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"groups"`
}

// getUserinfo 从 GitLab 获取用户信息。
func (p *GitLabProvider) getUserinfo(ctx context.Context, s *sessions.SessionState) (*gitlabUserinfo, error) {
	// Retrieve user info JSON
	// https://docs.gitlab.com/ee/integration/openid_connect_provider.html#shared-information

	// Build user info url from login url of GitLab instance
	userinfoURL := *p.LoginURL
	userinfoURL.Path = "/oauth/userinfo"

	var userinfo gitlabUserinfo
	err := requests.New(userinfoURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", tokenTypeBearer+" "+s.AccessToken).
		Do().
		UnmarshalInto(&userinfo)
	if err != nil {
		return nil, fmt.Errorf("error getting user info: %v", err)
	}

	return &userinfo, nil
}

// addProjectsToSession 将符合用户访问要求的项目添加到会话状态的分组列表中。
// 此方法在项目名称前加上 `project:` 前缀以指定分组类型。
func (p *GitLabProvider) addProjectsToSession(ctx context.Context, s *sessions.SessionState) {
	// Iterate over projects, check if oauth2-proxy can get project information on behalf of the user
	for _, project := range p.allowedProjects {
		projectInfo, err := p.getProjectInfo(ctx, s, project.Name)
		if err != nil {
			logger.Errorf("Warning: project info request failed: %v", err)
			continue
		}

		if projectInfo.Archived {
			logger.Errorf("Warning: project %s is archived", project.Name)
			continue
		}

		perms := projectInfo.Permissions.ProjectAccess
		if perms == nil {
			// use group project access as fallback
			perms = projectInfo.Permissions.GroupAccess
			// group project access is not set for this user then we give up
			if perms == nil {
				logger.Errorf("Warning: user %q has no project level access to %s",
					s.Email, project.Name)
				continue
			}
		}

		if perms.AccessLevel < project.AccessLevel {
			logger.Errorf(
				"Warning: user %q does not have the minimum required access level for project %q",
				s.Email,
				project.Name,
			)
			continue
		}

		s.Groups = append(s.Groups, formatProject(project))
	}
}

type gitlabPermissionAccess struct {
	AccessLevel int `json:"access_level"`
}

type gitlabProjectPermission struct {
	ProjectAccess *gitlabPermissionAccess `json:"project_access"`
	GroupAccess   *gitlabPermissionAccess `json:"group_access"`
}

type gitlabProjectInfo struct {
	Name              string                  `json:"name"`
	Archived          bool                    `json:"archived"`
	PathWithNamespace string                  `json:"path_with_namespace"`
	Permissions       gitlabProjectPermission `json:"permissions"`
}

// getProjectInfo 从 GitLab API 获取项目信息。
func (p *GitLabProvider) getProjectInfo(ctx context.Context, s *sessions.SessionState, project string) (*gitlabProjectInfo, error) {
	var projectInfo gitlabProjectInfo

	endpointURL := &url.URL{
		Scheme: p.LoginURL.Scheme,
		Host:   p.LoginURL.Host,
		Path:   "/api/v4/projects/",
	}

	err := requests.New(fmt.Sprintf("%s%s", endpointURL.String(), url.QueryEscape(project))).
		WithContext(ctx).
		SetHeader("Authorization", tokenTypeBearer+" "+s.AccessToken).
		Do().
		UnmarshalInto(&projectInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to get project info: %v", err)
	}

	return &projectInfo, nil
}

// formatProject 格式化项目名称以包含 `project:` 前缀。
func formatProject(project *gitlabProject) string {
	return gitlabProjectPrefix + project.Name
}

// RefreshSession 使用 OIDCProvider 实现刷新会话，但保留在 EnrichSession 阶段添加的自定义 GitLab 项目。
func (p *GitLabProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	nickname := s.User
	projects := getSessionProjects(s)
	// This will overwrite s.Groups with the new IDToken's `groups` claims
	// and s.User with the `sub` claim.
	refreshed, err := p.oidcRefreshFunc(ctx, s)
	if refreshed && err == nil {
		s.User = nickname
		s.Groups = append(s.Groups, projects...)
		s.Groups = deduplicateGroups(s.Groups)
	}
	return refreshed, err
}

// getSessionProjects 从会话状态中提取以 `project:` 为前缀的项目分组。
func getSessionProjects(s *sessions.SessionState) []string {
	var projects []string
	for _, group := range s.Groups {
		if strings.HasPrefix(group, gitlabProjectPrefix) {
			projects = append(projects, group)
		}
	}
	return projects
}

// deduplicateGroups 对分组列表进行去重。
func deduplicateGroups(groups []string) []string {
	groupSet := make(map[string]struct{})
	for _, group := range groups {
		groupSet[group] = struct{}{}
	}

	uniqueGroups := make([]string, 0, len(groupSet))
	for group := range groupSet {
		uniqueGroups = append(uniqueGroups, group)
	}
	return uniqueGroups
}
