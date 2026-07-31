"""Input models for the teams, team groups, roles, and users tools.

Everything in this domain is addressed by a numeric surrogate id — a team id, a
team group id, a role id, a user id — so every path parameter is validated with
`ge=1` and none of them needs percent encoding. Project locators appear only as
body values (`PUT /teams/{id}/projects`) and response values, never as path
segments.

Two shapes recur and are worth naming once:

* **Paginated list endpoints** use FOSSA's `page` / `pageSize` / `search` trio
  with a hard server-side cap of 50 per page, expressed here as `le=50`. This is
  a different convention from the `page` / `count` used elsewhere in the API, so
  the parameter is called `page_size` rather than `count` to keep the two from
  being confused.
* **Membership endpoints** take an `action` of add, remove, or replace over a
  list of ids. `replace` sets the assignment to exactly what is listed, so it
  removes anything not named; the models require a non-empty list on every
  action so an empty `replace` cannot silently clear a team.
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Sections of a team that can be fetched in one call. Each maps to a distinct
# FOSSA endpoint; the Literal is what keeps an invalid section a schema error at
# the client instead of a 404 from FOSSA.
TeamSection = Literal["team", "members", "projects", "release_groups"]
TEAM_SECTION_ORDER: tuple[TeamSection, ...] = ("team", "members", "projects", "release_groups")

# Sections that accept the pagination trio, and the narrower set that also
# accepts a sort order. `team` is a single-record read and takes neither.
PAGINATED_TEAM_SECTIONS: frozenset[str] = frozenset({"members", "projects", "release_groups"})
SORTABLE_TEAM_SECTIONS: frozenset[str] = frozenset({"projects", "release_groups"})

SortOrder = Literal["asc", "desc"]

# The three "what could I add to this team" endpoints.
AddableTeamTarget = Literal["users", "projects_and_release_groups", "release_group_projects"]

# What a team assignment update is changing, and how.
TeamAssignmentTarget = Literal["users", "projects", "release_groups"]
AssignmentAction = Literal["add", "remove", "replace"]

TeamGroupAction = Literal["create", "update", "delete"]
TeamGroupAssignmentTarget = Literal["teams", "users"]

RoleSection = Literal["roles", "permissions", "assignable"]
ROLE_SECTION_ORDER: tuple[RoleSection, ...] = ("roles", "permissions", "assignable")

RoleScope = Literal["organization", "team"]
RoleAction = Literal["create", "update", "delete"]

UserSort = Literal[
    "username_asc",
    "username_desc",
    "full_name_asc",
    "full_name_desc",
    "email_asc",
    "email_desc",
    "created_at_asc",
    "created_at_desc",
    "last_visit_asc",
    "last_visit_desc",
]


def _ordered_unique(values: list[str], order: tuple[str, ...]) -> list[str]:
    """Return `values` deduplicated and sorted into canonical `order`.

    Section order decides both the sequence of HTTP calls and the reported
    endpoint string, so it must not depend on the order the caller happened to
    list them in.
    """
    requested = set(values)
    return [section for section in order if section in requested]


class UserAssignment(BaseModel):
    """One user being added to, removed from, or re-roled in a team.

    The field names are FOSSA's body keys verbatim, so a validated instance
    dumps straight into the request body with no translation step. `roleId` is
    optional here and required by the enclosing model for the add and replace
    actions, which is where the action is known.
    """

    model_config = ConfigDict(extra="forbid")

    id: int = Field(ge=1)
    roleId: int | None = Field(default=None, ge=1)  # noqa: N815 - FOSSA body key


class TeamProjectFilters(BaseModel):
    """Filter criteria selecting the projects a team assignment applies to.

    FOSSA resolves these server-side, so the set of projects affected is not
    known before the call is made. That is what makes a filtered assignment an
    unbounded write.
    """

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1)
    labels: list[int] | None = None
    type: str | None = Field(default=None, min_length=1)
    lastRevisionWithin: str | None = Field(default=None, min_length=1)  # noqa: N815 - FOSSA key
    isPublic: bool | None = None  # noqa: N815 - FOSSA body key

    @model_validator(mode="after")
    def _check_not_empty(self) -> "TeamProjectFilters":
        if all(
            getattr(self, name) is None
            for name in ("title", "labels", "type", "lastRevisionWithin", "isPublic")
        ):
            raise ValueError("project_filters must set at least one filter when provided")
        if self.labels is not None and (not self.labels or any(v < 1 for v in self.labels)):
            raise ValueError("project_filters.labels must be a non-empty list of ids >= 1")
        return self


class RolePermission(BaseModel):
    """One permission granted by a custom role.

    Both values are validated by FOSSA against `GET /roles/all-permissions`
    rather than against a Literal here — the permission catalog is organization-
    and version-dependent, so pinning it in the schema would go stale.
    """

    model_config = ConfigDict(extra="forbid")

    resourceType: str = Field(min_length=1)  # noqa: N815 - FOSSA body key
    action: str = Field(min_length=1)


class TeamListInput(BaseModel):
    """Input model for fossa_list_teams."""

    model_config = ConfigDict(extra="forbid")

    page: int = Field(default=1, ge=1)
    # FOSSA caps this endpoint at 50 per page.
    page_size: int = Field(default=10, ge=1, le=50)
    search: str | None = Field(default=None, min_length=1, max_length=255)
    include_all_with_members: bool = False

    @model_validator(mode="after")
    def _check_deprecated_mode(self) -> "TeamListInput":
        if self.include_all_with_members:
            if self.search is not None:
                raise ValueError(
                    "search is not supported when include_all_with_members is set; "
                    "the unpaginated endpoint returns every team"
                )
            if self.page != 1 or self.page_size != 10:
                raise ValueError(
                    "page and page_size do not apply when include_all_with_members is set; "
                    "the unpaginated endpoint returns every team"
                )
        return self


class TeamReadInput(BaseModel):
    """Input model for fossa_get_team."""

    model_config = ConfigDict(extra="forbid")

    team_id: int = Field(ge=1)
    sections: list[TeamSection] = Field(min_length=1)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=10, ge=1, le=50)
    search: str | None = Field(default=None, min_length=1)
    sort: SortOrder | None = None

    @model_validator(mode="after")
    def _normalize_sections(self) -> "TeamReadInput":
        self.sections = _ordered_unique(  # type: ignore[assignment]
            list(self.sections), TEAM_SECTION_ORDER
        )

        requested = set(self.sections)
        if self.search is not None and not (requested & PAGINATED_TEAM_SECTIONS):
            raise ValueError(
                "search only applies to the members, projects, and release_groups sections"
            )
        if self.sort is not None and not (requested & SORTABLE_TEAM_SECTIONS):
            raise ValueError("sort only applies to the projects and release_groups sections")
        return self


class AddableTeamTargetsInput(BaseModel):
    """Input model for fossa_list_addable_team_targets."""

    model_config = ConfigDict(extra="forbid")

    team_id: int = Field(ge=1)
    target: AddableTeamTarget
    release_group_id: int | None = Field(default=None, ge=1)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=10, ge=1, le=50)
    search: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _check_target(self) -> "AddableTeamTargetsInput":
        if self.target == "release_group_projects":
            if self.release_group_id is None:
                raise ValueError(
                    "release_group_id is required when target is release_group_projects"
                )
            # This endpoint returns the whole set in one response and declares no
            # query parameters at all, so accepting them would be a lie.
            if self.search is not None:
                raise ValueError("search is not supported for target release_group_projects")
            if self.page != 1 or self.page_size != 10:
                raise ValueError(
                    "page and page_size are not supported for target release_group_projects"
                )
        elif self.release_group_id is not None:
            raise ValueError("release_group_id only applies when target is release_group_projects")
        return self


class TeamCreateInput(BaseModel):
    """Input model for fossa_create_team."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    default_role_id: int = Field(ge=1)
    auto_add_users: bool = False
    unique_identifier: str | None = Field(default=None, min_length=1)
    team_group_ids: list[int] | None = None

    @model_validator(mode="after")
    def _check_team_group_ids(self) -> "TeamCreateInput":
        if self.team_group_ids is not None:
            if not self.team_group_ids:
                raise ValueError("team_group_ids must name at least one team group when provided")
            if any(group_id < 1 for group_id in self.team_group_ids):
                raise ValueError("team_group_ids must all be >= 1")
        return self


class TeamUpdateInput(BaseModel):
    """Input model for fossa_update_team."""

    model_config = ConfigDict(extra="forbid")

    team_id: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1)
    default_role_id: int | None = Field(default=None, ge=1)
    auto_add_users: bool | None = None
    unique_identifier: str | None = Field(default=None, min_length=1)
    clear_unique_identifier: bool = False

    @model_validator(mode="after")
    def _check_something_changes(self) -> "TeamUpdateInput":
        if self.unique_identifier is not None and self.clear_unique_identifier:
            raise ValueError("Cannot set and clear unique_identifier in the same call")
        assigned = any(
            getattr(self, name) is not None
            for name in ("name", "default_role_id", "auto_add_users", "unique_identifier")
        )
        if not assigned and not self.clear_unique_identifier:
            raise ValueError("Provide at least one field to update, or set clear_unique_identifier")
        return self


class TeamDeleteInput(BaseModel):
    """Input model for fossa_delete_team."""

    model_config = ConfigDict(extra="forbid")

    team_id: int = Field(ge=1)


class TeamAssignmentInput(BaseModel):
    """Input model for fossa_update_team_assignments.

    One tool drives three FOSSA endpoints, so the validation here is what keeps
    the payloads from mixing: each target accepts exactly its own fields and
    rejects the others, and an unusable combination fails as a validation error
    before the write tier is even consulted.
    """

    model_config = ConfigDict(extra="forbid")

    team_id: int = Field(ge=1)
    target: TeamAssignmentTarget
    action: AssignmentAction
    users: list[UserAssignment] | None = None
    projects: list[str] | None = None
    all_projects: bool = False
    project_filters: TeamProjectFilters | None = None
    release_group_ids: list[int] | None = None

    @property
    def takes_assignments_away(self) -> bool:
        """True when this call can remove an assignment the team already has.

        "remove" takes named assignments away and "replace" sets the collection
        to exactly what is named, dropping everything else. `all_projects` and
        `project_filters` resolve server-side, so the number of projects the
        call touches is not knowable from the arguments — the unbounded-target
        case the DESTRUCTIVE tier exists for. Only a bounded "add" is exempt.
        """
        if self.action in ("remove", "replace"):
            return True
        return self.all_projects or self.project_filters is not None

    @model_validator(mode="after")
    def _check_target_fields(self) -> "TeamAssignmentInput":
        project_fields = (
            self.projects is not None or self.all_projects or (self.project_filters is not None)
        )

        if self.target == "users":
            if project_fields or self.release_group_ids is not None:
                raise ValueError(
                    "target 'users' accepts only the users field; "
                    "projects, all_projects, project_filters, and release_group_ids "
                    "belong to the other targets"
                )
            if not self.users:
                raise ValueError("users must name at least one user for target 'users'")
            if self.action in ("add", "replace") and any(
                user.roleId is None for user in self.users
            ):
                raise ValueError(f"roleId is required on every user for action '{self.action}'")

        elif self.target == "projects":
            if self.users is not None or self.release_group_ids is not None:
                raise ValueError(
                    "target 'projects' accepts only projects, all_projects, and project_filters"
                )
            selectors = [
                self.projects is not None,
                self.all_projects,
                self.project_filters is not None,
            ]
            if sum(selectors) != 1:
                raise ValueError(
                    "target 'projects' needs exactly one of projects, all_projects, "
                    "or project_filters"
                )
            if self.projects is not None:
                if not self.projects:
                    raise ValueError("projects must name at least one project locator")
                if any(not locator.strip() for locator in self.projects):
                    raise ValueError("projects must not contain blank entries")

        else:
            if self.users is not None or project_fields:
                raise ValueError("target 'release_groups' accepts only the release_group_ids field")
            if self.action == "replace":
                raise ValueError(
                    "FOSSA has no replace endpoint for team release groups; use 'add' or 'remove'"
                )
            if not self.release_group_ids:
                raise ValueError(
                    "release_group_ids must name at least one release group for "
                    "target 'release_groups'"
                )
            if any(group_id < 1 for group_id in self.release_group_ids):
                raise ValueError("release_group_ids must all be >= 1")

        return self


class TeamGroupReadInput(BaseModel):
    """Input model for fossa_get_team_groups."""

    model_config = ConfigDict(extra="forbid")

    team_group_id: int | None = Field(default=None, ge=1)


class TeamGroupManageInput(BaseModel):
    """Input model for fossa_manage_team_group.

    FOSSA requires both `name` and `defaultRoleId` on create *and* on update —
    the update endpoint is a full replacement, not a patch — so both are
    required for either action rather than optional.
    """

    model_config = ConfigDict(extra="forbid")

    action: TeamGroupAction
    team_group_id: int | None = Field(default=None, ge=1)
    name: str | None = Field(default=None, min_length=1)
    default_role_id: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _check_action_fields(self) -> "TeamGroupManageInput":
        if self.action == "create":
            if self.team_group_id is not None:
                raise ValueError("team_group_id must not be set when action is 'create'")
            if self.name is None or self.default_role_id is None:
                raise ValueError("name and default_role_id are required when action is 'create'")
        elif self.action == "update":
            if self.team_group_id is None:
                raise ValueError("team_group_id is required when action is 'update'")
            if self.name is None or self.default_role_id is None:
                raise ValueError(
                    "FOSSA replaces both fields on update, so name and default_role_id "
                    "are both required when action is 'update'"
                )
        else:
            if self.team_group_id is None:
                raise ValueError("team_group_id is required when action is 'delete'")
            if self.name is not None or self.default_role_id is not None:
                raise ValueError("name and default_role_id must not be set when action is 'delete'")
        return self


class TeamGroupAssignmentInput(BaseModel):
    """Input model for fossa_update_team_group_assignments."""

    model_config = ConfigDict(extra="forbid")

    team_group_id: int = Field(ge=1)
    target: TeamGroupAssignmentTarget
    action: AssignmentAction
    team_ids: list[int] | None = None
    users: list[UserAssignment] | None = None

    @property
    def takes_assignments_away(self) -> bool:
        """True when this call can remove an assignment the group already has.

        Every target here names an explicit list, so there is no unbounded case
        to consider — only the action matters.
        """
        return self.action in ("remove", "replace")

    @model_validator(mode="after")
    def _check_target_fields(self) -> "TeamGroupAssignmentInput":
        if self.target == "teams":
            if self.users is not None:
                raise ValueError("target 'teams' accepts only the team_ids field")
            if self.action == "replace":
                raise ValueError(
                    "FOSSA has no replace endpoint for the teams in a team group; "
                    "use 'add' or 'remove'"
                )
            if not self.team_ids:
                raise ValueError("team_ids must name at least one team for target 'teams'")
            if any(team_id < 1 for team_id in self.team_ids):
                raise ValueError("team_ids must all be >= 1")
        else:
            if self.team_ids is not None:
                raise ValueError("target 'users' accepts only the users field")
            if not self.users:
                raise ValueError("users must name at least one user for target 'users'")
            if self.action in ("add", "replace") and any(
                user.roleId is None for user in self.users
            ):
                raise ValueError(f"roleId is required on every user for action '{self.action}'")
        return self


class RoleListInput(BaseModel):
    """Input model for fossa_list_roles."""

    model_config = ConfigDict(extra="forbid")

    sections: list[RoleSection] = Field(min_length=1)

    @model_validator(mode="after")
    def _normalize_sections(self) -> "RoleListInput":
        self.sections = _ordered_unique(  # type: ignore[assignment]
            list(self.sections), ROLE_SECTION_ORDER
        )
        return self


class RoleManageInput(BaseModel):
    """Input model for fossa_manage_role."""

    model_config = ConfigDict(extra="forbid")

    action: RoleAction
    role_id: int | None = Field(default=None, ge=1)
    scope: RoleScope | None = None
    name: str | None = Field(default=None, min_length=1)
    description: str | None = Field(default=None, min_length=1)
    permissions: list[RolePermission] | None = None

    @model_validator(mode="after")
    def _check_action_fields(self) -> "RoleManageInput":
        if self.action == "create":
            if self.role_id is not None:
                raise ValueError("role_id must not be set when action is 'create'")
            if self.scope is None or self.name is None or self.description is None:
                raise ValueError(
                    "scope, name, and description are required when action is 'create'"
                )
        elif self.action == "update":
            if self.role_id is None:
                raise ValueError("role_id is required when action is 'update'")
            if self.scope is not None:
                raise ValueError("FOSSA does not allow a role's scope to change after creation")
            if self.name is None and self.description is None and self.permissions is None:
                raise ValueError(
                    "Provide at least one of name, description, or permissions to update"
                )
        else:
            if self.role_id is None:
                raise ValueError("role_id is required when action is 'delete'")
            if any(
                value is not None
                for value in (self.scope, self.name, self.description, self.permissions)
            ):
                raise ValueError(
                    "scope, name, description, and permissions must not be set "
                    "when action is 'delete'"
                )

        if self.permissions is not None and not self.permissions:
            raise ValueError(
                "permissions must name at least one permission when provided; "
                "omit it to leave the role's permissions unchanged"
            )
        return self


class UserListInput(BaseModel):
    """Input model for fossa_list_users."""

    model_config = ConfigDict(extra="forbid")

    user_id: int | None = Field(default=None, ge=1)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=10, ge=1, le=50)
    search: str | None = Field(default=None, min_length=1, max_length=255)
    sort: UserSort | None = None
    include_all: bool = False

    @model_validator(mode="after")
    def _check_mode(self) -> "UserListInput":
        if self.user_id is not None and self.include_all:
            raise ValueError("user_id and include_all select different endpoints; set only one")

        listing_arguments = [name for name in ("search", "sort") if getattr(self, name) is not None]
        if self.page != 1 or self.page_size != 10:
            listing_arguments.append("page/page_size")

        if self.user_id is not None and listing_arguments:
            raise ValueError(
                "page, page_size, search, and sort do not apply when user_id names one user"
            )
        if self.include_all and (self.search is not None or self.sort is not None):
            raise ValueError(
                "search and sort are not supported by the deprecated unpaginated user endpoint"
            )
        return self


class ServiceAccountCreateInput(BaseModel):
    """Input model for fossa_create_service_account.

    FOSSA requires at least one of an organization role or a team assignment; an
    account with neither would exist and be able to do nothing.
    """

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1)
    email: str | None = Field(default=None, min_length=1)
    full_name: str | None = Field(default=None, min_length=1)
    org_role_id: int | None = Field(default=None, ge=1)
    team_id: int | None = Field(default=None, ge=1)
    team_role_id: int | None = Field(default=None, ge=1)
    has_push_only_api_token: bool = False
    has_full_api_token: bool = False

    @model_validator(mode="after")
    def _check_assignment(self) -> "ServiceAccountCreateInput":
        if (self.team_id is None) != (self.team_role_id is None):
            raise ValueError("team_id and team_role_id must be set together or both unset")
        if self.org_role_id is None and self.team_id is None:
            raise ValueError("Provide org_role_id, or team_id with team_role_id, or both")
        return self


def dump_users(users: list[UserAssignment]) -> list[dict[str, Any]]:
    """Render validated user assignments as FOSSA body objects, omitting unset keys."""
    return [user.model_dump(exclude_none=True) for user in users]
