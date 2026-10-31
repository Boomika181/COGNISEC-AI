import secrets
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.appointment import HealthcareAppointment
from app.models.user import User
from app.schemas.healthcare import (
    DoctorResponse,
    DepartmentResponse,
    AppointmentCreateRequest,
    AppointmentResponse,
    DoctorProfileResponse
)


# Verified Clinical Departments of AyuSync MedCare Network
HOSPITAL_DEPARTMENTS: List[Dict[str, Any]] = [
    {
        "id": "cardiology",
        "name": "Cardiology & Cardiac Surgery",
        "code": "CARD",
        "icon": "🫀",
        "description": "Comprehensive cardiac care, advanced catheterization, primary angioplasty, and cardiac rehabilitation.",
        "doctor_count": 1
    },
    {
        "id": "neurology",
        "name": "Neurology & Stroke Care",
        "code": "NEUR",
        "icon": "🧠",
        "description": "Comprehensive stroke management, neurovascular interventions, epilepsy monitoring, and neuro-rehabilitation.",
        "doctor_count": 1
    },
    {
        "id": "pediatrics",
        "name": "Pediatrics & Child Health",
        "code": "PEDI",
        "icon": "👶",
        "description": "Neonatal intensive care (NICU Level-III), developmental pediatrics, and pediatric subspecialties.",
        "doctor_count": 1
    },
    {
        "id": "orthopedics",
        "name": "Orthopedics & Joint Replacement",
        "code": "ORTH",
        "icon": "🦴",
        "description": "Computer-navigated joint replacement, arthroscopic sports injury reconstruction, and trauma care.",
        "doctor_count": 1
    },
    {
        "id": "dermatology",
        "name": "Dermatology & Cosmetology",
        "code": "DERM",
        "icon": "✨",
        "description": "Clinical dermatology, phototherapy for chronic skin conditions, immunotherapy, and aesthetic care.",
        "doctor_count": 1
    },
    {
        "id": "general_medicine",
        "name": "General Medicine & Diabetology",
        "code": "GENM",
        "icon": "🩺",
        "description": "Comprehensive adult primary care, metabolic syndrome management, diabetes education, and geriatrics.",
        "doctor_count": 1
    }
]

# Verified Consultant Medical Staff Registry
HOSPITAL_DOCTORS: List[Dict[str, Any]] = [
    {
        "id": "doc-1",
        "name": "Dr. Boomika Ram",
        "degrees": "MBBS, MD, DM (Cardiology)",
        "dept": "cardiology",
        "dept_label": "Cardiology & Cardiac Surgery",
        "room": "Room 204, Tower B",
        "experience": "18+ Years",
        "reg": "KMC #84920",
        "fee": "₹1,200",
        "availability": "Available for Consultation",
        "opd_hours": "Mon–Sat • 09:00 AM – 01:00 PM",
        "avatar": "👩‍⚕️",
        "bio": "Senior Consultant Cardiologist specializing in adult interventional cardiology, primary coronary angioplasty, transcatheter aortic valve implantation (TAVI), and structural heart disease.",
        "associated_email": "dr.boomika@ayusync.med.in"
    },
    {
        "id": "doc-2",
        "name": "Dr. Sarah Lin, MD",
        "degrees": "MBBS, MS, MCh (Neurosurgery)",
        "dept": "neurology",
        "dept_label": "Neurology & Stroke Care",
        "room": "Room 112, Tower A",
        "experience": "22+ Years",
        "reg": "KMC #71294",
        "fee": "₹1,500",
        "availability": "Available for Consultation",
        "opd_hours": "Mon–Fri • 10:00 AM – 02:00 PM",
        "avatar": "👩‍⚕️",
        "bio": "Chief Neurosurgeon and Director of Stroke Program. Specializes in minimally invasive skull-base neurosurgery, intracranial aneurysms, and epilepsy surgical therapies.",
        "associated_email": "dr.sarah@aetheriahealth.org"
    },
    {
        "id": "doc-3",
        "name": "Dr. Sunita Mehra",
        "degrees": "MBBS, MD (Pediatrics), DNB",
        "dept": "pediatrics",
        "dept_label": "Pediatrics & Child Health",
        "room": "Room 305, Tower C",
        "experience": "15+ Years",
        "reg": "KMC #90214",
        "fee": "₹900",
        "availability": "Available for Consultation",
        "opd_hours": "Mon–Sat • 09:00 AM – 04:00 PM",
        "avatar": "👩‍⚕️",
        "bio": "Senior Consultant Pediatrician & Neonatologist leading the Level-III NICU. Expert in childhood infectious diseases, pediatric allergy screening, and infant growth development.",
        "associated_email": "dr.sunita@ayusync.med.in"
    },
    {
        "id": "doc-4",
        "name": "Dr. Vikramaditya Rao",
        "degrees": "MBBS, MS (Orthopedics), MCh Orth (UK)",
        "dept": "orthopedics",
        "dept_label": "Orthopedics & Joint Replacement",
        "room": "Room 108, Tower B",
        "experience": "19+ Years",
        "reg": "KMC #65812",
        "fee": "₹1,200",
        "availability": "Available for Consultation",
        "opd_hours": "Mon, Wed, Fri • 11:00 AM – 03:00 PM",
        "avatar": "👨‍⚕️",
        "bio": "Pioneer in robotic total knee and hip arthroplasty, arthroscopic cruciate ligament reconstructions, and sports medicine rehabilitation.",
        "associated_email": "dr.vikram@ayusync.med.in"
    },
    {
        "id": "doc-5",
        "name": "Dr. Ananya Sen",
        "degrees": "MBBS, MD (Dermatology, Venereology & Leprosy)",
        "dept": "dermatology",
        "dept_label": "Dermatology & Cosmetology",
        "room": "Room 215, Tower A",
        "experience": "12+ Years",
        "reg": "KMC #94821",
        "fee": "₹1,000",
        "availability": "Available for Consultation",
        "opd_hours": "Tue, Thu, Sat • 02:00 PM – 06:00 PM",
        "avatar": "👩‍⚕️",
        "bio": "Renowned clinical dermatologist specializing in chronic psoriasis phototherapy, pediatric atopic dermatitis, biological immunotherapy, and aesthetic laser rejuvenation.",
        "associated_email": "dr.ananya@ayusync.med.in"
    },
    {
        "id": "doc-6",
        "name": "Dr. Sandeep Verma",
        "degrees": "MBBS, MD (General Medicine), FCCP",
        "dept": "general_medicine",
        "dept_label": "General Medicine & Diabetology",
        "room": "Room 102, Tower A",
        "experience": "16+ Years",
        "reg": "KMC #81920",
        "fee": "₹800",
        "availability": "Available for Consultation",
        "opd_hours": "Mon–Sat • 08:30 AM – 12:30 PM",
        "avatar": "👨‍⚕️",
        "bio": "Senior Consultant Physician specializing in diabetic metabolic management, hypertensive disorders, geriatric preventive medicine, and pre-operative cardiac evaluations.",
        "associated_email": "dr.sandeep@ayusync.med.in"
    }
]


class HealthcareService:

    @staticmethod
    def get_departments() -> List[DepartmentResponse]:
        """Returns verified hospital departments catalog."""
        return [DepartmentResponse(**dept) for dept in HOSPITAL_DEPARTMENTS]

    @staticmethod
    def get_doctors(dept: Optional[str] = None) -> List[DoctorResponse]:
        """Returns verified hospital consultant staff, optionally filtered by department."""
        results = []
        clean_dept = (dept or "").strip().lower()
        for doc in HOSPITAL_DOCTORS:
            if clean_dept and clean_dept != "all" and doc["dept"].lower() != clean_dept:
                continue
            results.append(DoctorResponse(
                id=doc["id"],
                name=doc["name"],
                degrees=doc["degrees"],
                dept=doc["dept"],
                dept_label=doc["dept_label"],
                room=doc["room"],
                experience=doc["experience"],
                reg=doc["reg"],
                fee=doc["fee"],
                availability=doc["availability"],
                opd_hours=doc["opd_hours"],
                avatar=doc["avatar"],
                bio=doc["bio"],
                is_active=True
            ))
        return results

    @staticmethod
    def get_doctor_by_id(doctor_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves verified consultant by id."""
        clean_id = doctor_id.strip().lower()
        for doc in HOSPITAL_DOCTORS:
            if doc["id"].lower() == clean_id:
                return doc
        return None

    @staticmethod
    def check_slot_availability(db: Session, doctor_id: str, date: str, slot: str) -> bool:
        """
        Validates whether a specific consultation time slot is open for a doctor.
        Prevents double-booking.
        """
        existing = db.query(HealthcareAppointment).filter(
            HealthcareAppointment.doctor_id == doctor_id,
            HealthcareAppointment.appointment_date == date,
            HealthcareAppointment.time_slot == slot,
            HealthcareAppointment.status != "CANCELLED"
        ).first()
        return existing is None

    @staticmethod
    def create_appointment(
        db: Session,
        req: AppointmentCreateRequest,
        user_id: Optional[int] = None
    ) -> HealthcareAppointment:
        """
        Validates appointment details, checks doctor validity, ensures slot availability,
        and atomically persists the booking to the database.
        """
        doctor = HealthcareService.get_doctor_by_id(req.doctor_id)
        if not doctor:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Selected doctor '{req.doctor_id}' is not in the verified hospital registry."
            )

        # Ensure slot is available
        is_open = HealthcareService.check_slot_availability(
            db=db,
            doctor_id=req.doctor_id,
            date=req.appointment_date,
            slot=req.time_slot
        )
        if not is_open:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"The selected time slot ({req.time_slot} on {req.appointment_date}) is already booked. Please choose another slot."
            )

        # Generate cryptographic, human-readable hospital reference token
        ref_id = f"AYU-{datetime.now().year}-{secrets.token_hex(3).upper()}"

        appointment = HealthcareAppointment(
            reference_id=ref_id,
            patient_name=req.patient_name,
            patient_phone=req.patient_phone,
            patient_email=req.patient_email,
            department=doctor["dept_label"],
            doctor_id=doctor["id"],
            doctor_name=doctor["name"],
            appointment_date=req.appointment_date,
            time_slot=req.time_slot,
            consultation_mode=req.consultation_mode,
            room=doctor["room"],
            status="CONFIRMED",
            user_id=user_id
        )
        db.add(appointment)
        db.commit()
        db.refresh(appointment)
        return appointment

    @staticmethod
    def get_appointments(
        db: Session,
        email: Optional[str] = None,
        user_id: Optional[int] = None,
        limit: int = 50
    ) -> List[HealthcareAppointment]:
        """Queries persisted appointments for patient or authenticated session."""
        query = db.query(HealthcareAppointment)
        if user_id:
            query = query.filter(HealthcareAppointment.user_id == user_id)
        elif email:
            query = query.filter(HealthcareAppointment.patient_email == email.strip().lower())
        return query.order_by(HealthcareAppointment.created_at.desc()).limit(limit).all()

    @staticmethod
    def get_doctor_details_for_user(user: User) -> Optional[Dict[str, Any]]:
        """Maps authenticated user account to registered hospital doctor profile."""
        user_email = (user.email or "").strip().lower()
        for doc in HOSPITAL_DOCTORS:
            if doc.get("associated_email", "").strip().lower() == user_email:
                return doc
        if user.role.upper() in ("DOCTOR", "ADMIN"):
            # Generic fallback for provisioned clinical officer
            return {
                "name": user.name,
                "dept_label": "Clinical Medicine & Consultation",
                "reg": f"KMC #{user.id * 1000 + 492}",
                "room": "Room 204, Tower B"
            }
        return None
