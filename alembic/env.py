from __future__ import with_statement
from alembic import context
from sqlalchemy import engine_from_config, pool
from logging.config import fileConfig

import os
import sys
import glob

parent_dir = os.path.abspath(os.path.join(os.getcwd()))
sys.path.append(parent_dir)
from viper.core.database import Base  # noqa
from viper.core.config import __config__ as cfg  # noqa

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_online(db_file_path=None):
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    if not db_file_path:
        raise Exception("need to provide db file path (e.g. \"/home/user/.viper/viper.db\"")

    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        url="sqlite:///{}".format(db_file_path),
        prefix='sqlalchemy.',
        poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True
        )

        with context.begin_transaction():
            context.run_migrations()


dbs = [("{}/viper.db".format(cfg.get("paths").storage_path))]
#dbs.extend(glob.glob("{}/projects/*/viper.db".format(cfg.get("paths").storage_path)))

for db in dbs:
    print("running on: {}".format(db))
    run_migrations_online(db)
