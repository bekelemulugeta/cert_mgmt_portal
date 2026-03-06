from sqlalchemy import create_engine, inspect

# Update this with your real DB URL
engine = create_engine(
    "postgresql+psycopg2://postgres:Love#me#3756!@localhost/cert_mgmt"
)

insp = inspect(engine)

for table_name in insp.get_table_names():
    print("\n==============================")
    print(f"TABLE: {table_name}")
    print("==============================")

    # Columns
    print("\nColumns:")
    for col in insp.get_columns(table_name):
        print(f"  {col['name']}  |  {col['type']}  |  nullable={col['nullable']}  |  default={col['default']}")

    # Primary Key
    pk = insp.get_pk_constraint(table_name)
    print("\nPrimary Key:", pk["constrained_columns"])

    # Foreign Keys
    print("\nForeign Keys:")
    for fk in insp.get_foreign_keys(table_name):
        print(f"  {fk['constrained_columns']}  →  {fk['referred_table']}.{fk['referred_columns']}")

    # Indexes
    print("\nIndexes:")
    for ix in insp.get_indexes(table_name):
        print(f"  {ix['name']}  columns={ix['column_names']}")
