<?php

namespace League\OAuth2\Client\Test\Token;

use Firebase\JWT\Key;
use League\OAuth2\Client\Token\AppleAccessToken;
use PHPUnit\Framework\TestCase;
use Mockery as m;

class AppleAccessTokenTest extends TestCase
{
    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testCreatingAccessToken()
    {
        $externalJWTMock = m::mock('overload:Firebase\JWT\JWT');
        $externalJWTMock->shouldReceive('decode')
            ->with('something', m::type(Key::class))
            ->once()
            ->andReturn([
                'sub' => '123.abc.123',
                'email_verified' => true,
                'email' => 'john@doe.com',
                'is_private_email' => true
            ]);

        $key = new Key('examplekey', 'RS256');
        $accessToken = new AppleAccessToken([$key], [
            'access_token' => 'access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'abc.0.def',
            'id_token' => 'something'
        ]);
        $this->assertEquals('something', $accessToken->getIdToken());
        $this->assertEquals('123.abc.123', $accessToken->getResourceOwnerId());
        $this->assertEquals('access_token', $accessToken->getToken());
        $this->assertEquals('john@doe.com', $accessToken->getEmail());
        $this->assertTrue($accessToken->isPrivateEmail());

        $this->assertTrue(true);
    }

    public function testCreateFailsBecauseNoIdTokenIsSet()
    {
        $this->expectException('\InvalidArgumentException');
        $this->expectExceptionMessage('Required option not passed: "id_token"');

        $key = new Key('examplekey', 'RS256');
        new AppleAccessToken([$key], [
            'access_token' => 'access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'abc.0.def'
        ]);
    }

    public function testCreatingRefreshToken()
    {
        $refreshToken = new AppleAccessToken([], [
            'access_token' => 'access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600
        ]);
        $this->assertEquals('access_token', $refreshToken->getToken());
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testCreatingAccessTokenFailsBecauseNoDecodingIsPossible()
    {
        $this->expectException('\Exception');
        $this->expectExceptionMessage('Got no data within "id_token"!');

        $externalJWTMock = m::mock('overload:Firebase\JWT\JWT');
        $externalJWTMock->shouldReceive('decode')
            ->with('something', m::type(Key::class))
            ->once()
            ->andReturnNull();

        $key = new Key('examplekey', 'RS256');
        new AppleAccessToken([$key], [
            'access_token' => 'access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'abc.0.def',
            'id_token' => 'something'
        ]);
    }
}
