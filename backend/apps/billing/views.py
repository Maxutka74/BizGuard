from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import PurchaseOrder
from .serializers import CheckoutSerializer, CompleteCheckoutSerializer, PurchaseOrderSerializer
from .services import BillingError, complete_checkout, create_checkout, plan_catalog, reissue_legacy_key


class BillingProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        orders = PurchaseOrder.objects.select_related("generated_license_key").filter(user=request.user)
        return Response({
            "user": {
                "id": str(request.user.id),
                "email": request.user.email,
                "name": request.user.name,
                "avatar": request.user.avatar_url,
            },
            "plans": plan_catalog(),
            "orders": PurchaseOrderSerializer(orders, many=True).data,
        })


class CheckoutView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = "billing_checkout"

    def post(self, request):
        serializer = CheckoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            payload = create_checkout(
                request.user,
                serializer.validated_data["plan"],
                serializer.validated_data.get("activationCount", 1),
            )
        except BillingError as exc:
            return Response({"detail": exc.detail, "code": exc.code}, status=400)
        return Response(payload)


class CompleteCheckoutView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = "billing_complete"

    def post(self, request):
        serializer = CompleteCheckoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            result = complete_checkout(request.user, serializer.validated_data["sessionId"])
        except BillingError as exc:
            return Response({"detail": exc.detail, "code": exc.code}, status=400)
        return Response({
            "order": PurchaseOrderSerializer(result["order"]).data,
            "plaintextKey": result["plaintextKey"],
            "alreadyCompleted": result["alreadyCompleted"],
        })


class ReissueLegacyKeyView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = "billing_reissue"

    def post(self, request, order_id):
        try:
            result = reissue_legacy_key(request.user, order_id)
        except BillingError as exc:
            status_code = 404 if exc.code == "order_not_found" else 400
            return Response({"detail": exc.detail, "code": exc.code}, status=status_code)
        return Response({
            "order": PurchaseOrderSerializer(result["order"]).data,
            "plaintextKey": result["plaintextKey"],
            "reissued": result["reissued"],
        })
