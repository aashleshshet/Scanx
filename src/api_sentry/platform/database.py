"""Version-one relational storage; all query parameters are bound by SQLAlchemy."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import JSON, DateTime, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


class Base(DeclarativeBase):
    pass


class Record(Base):
    __tablename__ = "workspace_records"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    data: Mapped[dict] = mapped_column(JSON)


class Store:
    def __init__(self, url):
        options = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, pool_pre_ping=True, **options)

    def migrate(self):
        Base.metadata.create_all(self.engine)

    def put(self, kind, data, record_id=None):
        key = record_id or str(uuid4())
        with Session(self.engine) as session, session.begin():
            item = session.get(Record, key)
            if item:
                if item.kind != kind:
                    raise ValueError("Record type mismatch")
                item.data = data
            else:
                session.add(Record(id=key, kind=kind, data=data, created=datetime.now(UTC)))
        return key

    def get(self, kind, key):
        with Session(self.engine) as session:
            item = session.get(Record, key)
            return dict(item.data) if item and item.kind == kind else None

    def list(self, kind, limit=200):
        with Session(self.engine) as session:
            items = session.scalars(
                select(Record)
                .where(Record.kind == kind)
                .order_by(Record.created.desc())
                .limit(limit)
            )
            return [{"id": x.id, **x.data} for x in items]

    def delete(self, kind, key):
        with Session(self.engine) as session, session.begin():
            item = session.get(Record, key)
            if item and item.kind == kind:
                session.delete(item)

    def audit(self, action, record_id=""):
        self.put(
            "audit", {"action": action, "record_id": record_id, "at": datetime.now(UTC).isoformat()}
        )
