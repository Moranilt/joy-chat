package user

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	PASSWORD_MIN_LENGTH = 8

	ERROR_PASSWORD_MIN_LENGTH = "provide password with min length %d"
)

type UserController interface {
	CreateUser(cur CreateUserRequest) (*CreateUserResponse, error)
	GetByEmailAndPassword(req EmailAndPasswordRequest) (*EmailAndPasswordResponse, error)
	UpdateLastLogin(userId string) error
	GetWithoutID(userId string) (*UserWithoutID, error)
	Update(userId string, req UserUpdateRequest) (bool, error)
	Delete(userId string) (bool, error)
	ChangePassword(userId string, req ChangePasswordRequest) error
	AllUsers() ([]AdminUsersResponse, error)
	GetWithID(userId string) (*AdminUsersResponse, error)
	UpdateAllFields(userId string, req UpdateAllFieldsRequest) error
	DeleteUsers(ids []string) error
}

type UserClient struct {
	db *sqlx.DB
}

func NewUserClient(db *sqlx.DB) UserController {
	return &UserClient{
		db: db,
	}
}

func (u *UserClient) DeleteUsers(ids []string) error {
	_, err := u.db.Exec("DELETE FROM users WHERE id=ANY($1)", pq.Array(ids))
	if err != nil {
		return err
	}

	return nil
}

func (u *UserClient) UpdateAllFields(userId string, req UpdateAllFieldsRequest) error {
	var updateString []string

	if req.Email != nil {
		updateString = append(updateString, fmt.Sprintf("email='%s'", *req.Email))
	}

	if req.Firstname != nil {
		updateString = append(updateString, fmt.Sprintf("firstname='%s'", *req.Firstname))
	}

	if req.Lastname != nil {
		updateString = append(updateString, fmt.Sprintf("lastname='%s'", *req.Lastname))
	}

	if req.Patronymic != nil {
		updateString = append(updateString, fmt.Sprintf("patronymic='%s'", *req.Patronymic))
	}

	if req.RoleId != nil {
		updateString = append(updateString, fmt.Sprintf("role_id=%d", *req.RoleId))
	}

	query := fmt.Sprintf("UPDATE users SET %s WHERE id=$1", strings.Join(updateString, ", "))
	_, err := u.db.Exec(query, userId)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserClient) GetWithID(userId string) (*AdminUsersResponse, error) {
	var user AdminUsersResponse
	err := u.db.Get(&user, "SELECT id, firstname, lastname, patronymic, email, role_id, last_login FROM users WHERE id=$1", userId)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (u *UserClient) AllUsers() ([]AdminUsersResponse, error) {
	var users []AdminUsersResponse
	err := u.db.Select(&users, "SELECT id, firstname, lastname, patronymic, email, role_id, last_login FROM users")
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (u *UserClient) ChangePassword(userId string, req ChangePasswordRequest) error {
	if len(req.NewPassword) < PASSWORD_MIN_LENGTH {
		return fmt.Errorf(ERROR_PASSWORD_MIN_LENGTH, PASSWORD_MIN_LENGTH)
	}

	row := u.db.QueryRow("SELECT password FROM users WHERE id=$1", userId)
	if row.Err() != nil {
		return row.Err()
	}

	var hashedPass string
	err := row.Scan(&hashedPass)
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(req.OldPassword)); err != nil {
		return errors.Join(errors.New("not valid password"), err)
	}
	newPass, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 14)
	if err != nil {
		return err
	}

	_, err = u.db.Exec("UPDATE users SET password=$1 WHERE id=$2", newPass, userId)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserClient) Delete(userId string) (bool, error) {
	_, err := u.db.Exec("DELETE FROM users WHERE id=$1", userId)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (u *UserClient) Update(userId string, req UserUpdateRequest) (bool, error) {
	if req.Firstname == nil && req.Lastname == nil && req.Patronymic == nil {
		return false, errors.New("provide at least one field to update")
	}

	var updateString []string

	if req.Firstname != nil {
		updateString = append(updateString, fmt.Sprintf("firstname='%s'", *req.Firstname))
	}

	if req.Lastname != nil {
		updateString = append(updateString, fmt.Sprintf("lastname='%s'", *req.Lastname))
	}

	if req.Patronymic != nil {
		updateString = append(updateString, fmt.Sprintf("patronymic='%s'", *req.Patronymic))
	}

	query := fmt.Sprintf("UPDATE users SET %s WHERE id=$1", strings.Join(updateString, ", "))
	_, err := u.db.Exec(query, userId)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (u *UserClient) GetWithoutID(userId string) (*UserWithoutID, error) {
	row := u.db.QueryRowx("SELECT firstname, lastname, patronymic, email, role_id FROM users WHERE id=$1", userId)

	var ur UserWithoutID
	err := row.StructScan(&ur)
	if err != nil {
		return nil, err
	}

	return &ur, nil
}

func (u *UserClient) UpdateLastLogin(userId string) error {
	_, err := u.db.Exec("UPDATE users SET last_login=now() WHERE id=$1", userId)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserClient) GetByEmailAndPassword(req EmailAndPasswordRequest) (*EmailAndPasswordResponse, error) {
	_, err := mail.ParseAddress(req.Email)
	if err != nil {
		return nil, fmt.Errorf("email %q is not valid", req.Email)
	}

	result := u.db.QueryRowx(
		"SELECT id, password, firstname, lastname, patronymic, role_id FROM users WHERE email=$1",
		req.Email,
	)

	var resp EmailAndPasswordResponse
	err = result.StructScan(&resp)
	if err != nil {
		return nil, err
	}

	if resp.Password == "" {
		return nil, errors.New("user not found")
	}

	return &resp, nil
}

func (u *UserClient) CreateUser(cur CreateUserRequest) (*CreateUserResponse, error) {
	cur.Password = strings.TrimSpace(cur.Password)
	cur.Email = strings.TrimSpace(cur.Email)
	cur.Firstname = strings.TrimSpace(cur.Firstname)
	cur.Lastname = strings.TrimSpace(cur.Lastname)
	trimmedPatronymic := strings.TrimSpace(*cur.Patronymic)
	cur.Patronymic = &trimmedPatronymic

	_, err := mail.ParseAddress(cur.Email)
	if err != nil {
		return nil, fmt.Errorf("email %q is not valid", cur.Email)
	}

	if len(cur.Password) < 8 {
		return nil, fmt.Errorf("provide password with min length %d", PASSWORD_MIN_LENGTH)
	}

	password, err := bcrypt.GenerateFromPassword([]byte(cur.Password), 14)
	if err != nil {

		return nil, errors.New("cannot create password hash")
	}

	result := u.db.QueryRowx(
		`INSERT INTO users (firstname, lastname, patronymic, email, password)
		VALUES ($1, $2, $3, $4, $5) RETURNING id, role_id`,
		cur.Firstname,
		cur.Lastname,
		cur.Patronymic,
		cur.Email,
		string(password),
	)
	if err != nil {
		return nil, err
	}

	var dbResp CreateUserResponse
	err = result.StructScan(&dbResp)
	if err != nil {
		return nil, err
	}

	return &dbResp, nil
}
