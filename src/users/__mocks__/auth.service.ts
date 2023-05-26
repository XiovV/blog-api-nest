
export const AuthService = jest.fn().mockReturnValue({
    generateTokenPair: jest.fn().mockResolvedValue({})
})