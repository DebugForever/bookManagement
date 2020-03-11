# 使用环境变量来使得应用更安全
class Config:
    SECRET_KEY = '3e9d543c2f'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def init_app(app):
        pass


class DevConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'mysql://book_manager:password@localhost/BookManagement'
    DEBUG = True


class TestConfig(Config):
    TESTING = True


class ProdConfig(Config):
    pass


config = {
    'dev': DevConfig,
    'test': TestConfig,
    'production': ProdConfig,
    'default': DevConfig
}
