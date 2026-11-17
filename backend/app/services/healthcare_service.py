import secrets
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy import or_, and_
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
        "available_days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
        "available_slots": ["09:00 AM", "09:45 AM", "10:30 AM", "11:30 AM", "12:15 PM"],
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
        "available_days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
        "available_slots": ["10:00 AM", "10:45 AM", "11:30 AM", "12:30 PM", "01:30 PM"],
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
        "available_days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
        "available_slots": ["09:30 AM", "10:30 AM", "11:30 AM", "02:00 PM", "03:30 PM"],
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
        "available_days": ["Mon", "Wed", "Fri"],
        "available_slots": ["11:00 AM", "11:45 AM", "12:30 PM", "01:30 PM", "02:30 PM"],
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
        "available_days": ["Tue", "Thu", "Sat"],
        "available_slots": ["02:00 PM", "02:45 PM", "03:30 PM", "04:30 PM", "05:30 PM"],
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
        "available_days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
        "available_slots": ["08:30 AM", "09:15 AM", "10:00 AM", "11:00 AM", "12:00 PM"],
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
                is_active=True,
                available_days=list(doc.get("available_days", [])),
                available_slots=list(doc.get("available_slots", []))
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
    def validate_doctor_schedule(doctor: Dict[str, Any], appointment_date: str, time_slot: str) -> None:
        """
        Verifies that the requested date's weekday and time_slot match the doctor's configured OPD schedule.
        """
        try:
            parsed_date = datetime.strptime(appointment_date.strip(), "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid appointment date format. Expected YYYY-MM-DD."
            )

        weekday_abbr = parsed_date.strftime("%a")  # Mon, Tue, Wed, Thu, Fri, Sat, Sun
        allowed_days = doctor.get("available_days") or []
        if allowed_days and weekday_abbr not in allowed_days:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{doctor['name']} does not hold OPD on {parsed_date.strftime('%A')}. Available OPD days: {', '.join(allowed_days)}."
            )

        allowed_slots = doctor.get("available_slots") or []
        if allowed_slots and time_slot.strip() not in allowed_slots:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Time slot '{time_slot}' is not within {doctor['name']}'s OPD schedule ({doctor['opd_hours']})."
            )

    @staticmethod
    def get_doctor_slots_for_date(db: Session, doctor_id: str, appointment_date: str) -> Dict[str, Any]:
        """Returns configured OPD slots and live availability for a doctor on a given date."""
        doctor = HealthcareService.get_doctor_by_id(doctor_id)
        if not doctor:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Doctor '{doctor_id}' not found."
            )
        try:
            parsed_date = datetime.strptime(appointment_date.strip(), "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid date format. Expected YYYY-MM-DD."
            )

        weekday_abbr = parsed_date.strftime("%a")
        allowed_days = doctor.get("available_days") or []
        is_opd_day = (weekday_abbr in allowed_days) if allowed_days else True

        booked_rows = db.query(HealthcareAppointment.time_slot).filter(
            HealthcareAppointment.doctor_id == doctor["id"],
            HealthcareAppointment.appointment_date == appointment_date.strip(),
            HealthcareAppointment.status == "CONFIRMED"
        ).all()
        booked_slots = {r[0] for r in booked_rows}

        slots = []
        for slot in doctor.get("available_slots", []):
            slots.append({
                "slot": slot,
                "available": bool(is_opd_day and slot not in booked_slots)
            })

        return {
            "doctor_id": doctor["id"],
            "doctor_name": doctor["name"],
            "date": appointment_date.strip(),
            "weekday": parsed_date.strftime("%A"),
            "is_opd_day": is_opd_day,
            "available_days": allowed_days,
            "opd_hours": doctor["opd_hours"],
            "slots": slots,
        }

    @staticmethod
    def check_slot_availability(db: Session, doctor_id: str, date: str, slot: str) -> bool:
        """
        Validates whether a specific consultation time slot is open for a doctor.
        Only CONFIRMED appointments permanently occupy a slot so abandoned pending or failed attempts do not block slots.
        """
        existing = db.query(HealthcareAppointment).filter(
            HealthcareAppointment.doctor_id == doctor_id,
            HealthcareAppointment.appointment_date == date,
            HealthcareAppointment.time_slot == slot,
            HealthcareAppointment.status == "CONFIRMED"
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
            patient_name=req.patient_name.strip(),
            patient_phone=req.patient_phone.strip(),
            patient_email=req.patient_email.strip().lower(),
            department=doctor["dept_label"],
            doctor_id=doctor["id"],
            doctor_name=doctor["name"],
            appointment_date=req.appointment_date.strip(),
            time_slot=req.time_slot.strip(),
            consultation_mode=req.consultation_mode.strip() if req.consultation_mode else "In-Person OPD Visit",
            consultation_fee=doctor["fee"],
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
        """
        Queries persisted patient appointments.
        Excludes PENDING_VERIFICATION, FAILED, and EXPIRED records so unverified bookings never show as confirmed.
        """
        query = db.query(HealthcareAppointment).filter(
            HealthcareAppointment.status.in_(["CONFIRMED", "CANCELLED"])
        )
        clean_email = email.strip().lower() if email else None
        if user_id and clean_email:
            query = query.filter(
                or_(
                    HealthcareAppointment.user_id == user_id,
                    and_(
                        HealthcareAppointment.user_id.is_(None),
                        HealthcareAppointment.patient_email == clean_email
                    )
                )
            )
        elif user_id:
            query = query.filter(HealthcareAppointment.user_id == user_id)
        elif clean_email:
            query = query.filter(HealthcareAppointment.patient_email == clean_email)
        return query.order_by(HealthcareAppointment.created_at.desc()).limit(limit).all()

    @staticmethod
    def cancel_appointment(
        db: Session,
        reference_id: str,
        current_user: Optional[User] = None,
        patient_email: Optional[str] = None
    ) -> HealthcareAppointment:
        """
        Cancels an appointment subject to patient ownership or doctor authorization rules.
        """
        apt = db.query(HealthcareAppointment).filter(
            HealthcareAppointment.reference_id == reference_id
        ).first()
        if not apt:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Appointment '{reference_id}' not found in hospital registry."
            )

        if current_user:
            if current_user.role.upper() not in ("DOCTOR", "ADMIN"):
                # Patient can only cancel their own appointment
                is_owner = (apt.user_id and apt.user_id == current_user.id) or (
                    apt.patient_email and apt.patient_email.strip().lower() == current_user.email.strip().lower()
                )
                if not is_owner:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Unauthorized: You can only cancel your own appointments."
                    )
        elif patient_email:
            if not apt.patient_email or apt.patient_email.strip().lower() != patient_email.strip().lower():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Unauthorized: Email address does not match appointment record."
                )

        if apt.status == "CANCELLED":
            return apt

        apt.status = "CANCELLED"
        db.commit()
        db.refresh(apt)
        return apt

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
