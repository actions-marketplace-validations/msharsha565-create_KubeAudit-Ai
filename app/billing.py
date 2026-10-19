import os
import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, PlanTier
from app.auth import get_current_user

router = APIRouter(prefix="/v1/billing", tags=["billing"])

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_placeholder")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID_PRO = os.getenv("STRIPE_PRICE_ID_PRO", "price_pro_default")


@router.post("/checkout")
def create_checkout_session(
    user: User = Depends(get_current_user),
    success_url: str = "https://kubeaudit.ai/billing/success",
    cancel_url: str = "https://kubeaudit.ai/billing/cancel",
):
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            customer_email=user.email,
            line_items=[{"price": STRIPE_PRICE_ID_PRO, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={"user_id": str(user.id)},
        )
        return {"checkout_url": session.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook signature error: {str(e)}")

    event_type = event["type"]
    data_object = event["data"]["object"]

    if event_type == "customer.subscription.created":
        user_id = data_object.get("metadata", {}).get("user_id")
        if user_id:
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.subscription_tier = PlanTier.PRO
                user.subscription_status = "active"
                user.stripe_customer_id = data_object.get("customer")
                db.commit()

    elif event_type == "customer.subscription.deleted":
        customer_id = data_object.get("customer")
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        if user:
            user.subscription_tier = PlanTier.FREE
            user.subscription_status = "canceled"
            db.commit()

    return {"status": "success"}
