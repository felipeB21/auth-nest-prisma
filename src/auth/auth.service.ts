import { Injectable, UnauthorizedException } from '@nestjs/common';
import { LoginUserDto } from './dto/auth.dto';
import { UserService } from 'src/user/user.service';
import { compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async login(loginUserDto: LoginUserDto) {
    const user = await this.validateUser(loginUserDto);

    const payload = {
      username: user.email,
      sub: {
        name: user.name,
      },
    };

    return {
      user,
      backendTokens: {
        accessToken: await this.jwtService.signAsync(payload, {
          expiresIn: '5h',
          secret: process.env.JWT_SECRET,
        }),
        refreshToken: await this.jwtService.signAsync(payload, {
          expiresIn: '7d',
          secret: process.env.JWT_REFRESH_SECRET,
        }),
      },
    };
  }

  async validateUser(loginUserDto: LoginUserDto) {
    const user = await this.userService.findByEmail(loginUserDto.email);

    if (user && (await compare(loginUserDto.password, user.password))) {
      const { password, ...result } = user;
      return result;
    }

    throw new UnauthorizedException('Invalid credentials');
  }

  async refreshToken(user: any) {
    const payload = {
      username: user.username,
      sub: user.sub,
    };

    return {
      accesToken: await this.jwtService.signAsync(payload, {
        expiresIn: '5h',
        secret: process.env.JWT_SECRET,
      }),
      refreshToken: await this.jwtService.signAsync(payload, {
        expiresIn: '7d',
        secret: process.env.JWT_REFRESH_SECRET,
      }),
    };
  }
}
