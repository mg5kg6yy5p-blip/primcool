from pydantic import BaseModel, EmailStr, Field

from app.models import ConsultSubmission


class ConsultRequest(BaseModel):
    fname: str = Field(min_length=1, max_length=120)
    lname: str = Field(min_length=1, max_length=120)
    email: EmailStr
    phone: str = Field(default="", max_length=40)
    company: str = Field(default="", max_length=200)
    tier: str = Field(min_length=1, max_length=40)
    msg: str = Field(default="", max_length=4000)


class ConsultResponse(BaseModel):
    ok: bool


class ConsultSubmissionOut(BaseModel):
    id: str
    fname: str
    lname: str
    email: str
    phone: str
    company: str
    tier: str
    msg: str
    created_at: str

    @classmethod
    def from_model(cls, row: ConsultSubmission) -> "ConsultSubmissionOut":
        return cls(
            id=str(row.id),
            fname=row.fname,
            lname=row.lname,
            email=row.email,
            phone=row.phone,
            company=row.company,
            tier=row.tier,
            msg=row.msg,
            created_at=row.created_at.isoformat(),
        )


class ConsultSubmissionList(BaseModel):
    submissions: list[ConsultSubmissionOut]
