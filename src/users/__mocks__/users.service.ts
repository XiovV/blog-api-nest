import { userStub } from "../stubs/user.stub";

export const UsersService = jest.fn().mockReturnValue({
    create: jest.fn().mockResolvedValue(userStub())
})