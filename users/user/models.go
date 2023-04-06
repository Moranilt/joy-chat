package user

type CreateUserRequest struct {
	Firstname  string  `json:"firstname"`
	Lastname   string  `json:"lastname"`
	Patronymic *string `json:"patronymic"`
	Email      string  `json:"email"`
	Password   string  `json:"password"`
}

type CreateUserResponse struct {
	UserId string `json:"id" db:"id"`
	RoleId int    `json:"role_id" db:"role_id"`
}

type EmailAndPasswordRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type EmailAndPasswordResponse struct {
	Password   string  `json:"password" db:"password"`
	ID         string  `json:"id" db:"id"`
	Firstname  string  `json:"firstname" db:"firstname"`
	Lastname   string  `json:"lastname" db:"lastname"`
	Patronymic *string `json:"patronymic" db:"patronymic"`
	RoleId     int     `json:"role_id" db:"role_id"`
}

type UserWithoutID struct {
	Firstname  string  `json:"firstname" db:"firstname"`
	Lastname   string  `json:"lastname" db:"lastname"`
	Patronymic *string `json:"patronymic" db:"patronymic"`
	RoleId     int     `json:"role_id" db:"role_id"`
	Email      string  `json:"email" db:"email"`
}

type UserUpdateRequest struct {
	Firstname  *string `json:"firstname"`
	Lastname   *string `json:"lastname"`
	Patronymic *string `json:"patronymic"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type AdminUsersResponse struct {
	ID         string  `json:"id" db:"id"`
	Firstname  string  `json:"firstname" db:"firstname"`
	Lastname   string  `json:"lastname" db:"lastname"`
	Patronymic string  `json:"patronymic" db:"patronymic"`
	RoleId     int     `json:"role_id" db:"role_id"`
	Email      string  `json:"email" db:"email"`
	LastLogin  *string `json:"last_login" db:"last_login"`
}

type UpdateAllFieldsRequest struct {
	Firstname  *string `json:"firstname"`
	Lastname   *string `json:"lastname"`
	Patronymic *string `json:"patronymic"`
	Email      *string `json:"email" db:"email"`
	RoleId     *int    `json:"role_id" db:"role_id"`
}
