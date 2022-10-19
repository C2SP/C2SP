#! /usr/bin/env python3

# This is the reference implementation for groups jq255e and jq255s. It
# also includes functions for key exchange (ECDH), signature generation
# and verification (Schnorr signatures), and hash-to-curve.
#
# WARNING: This implementation is mathematically correct, but not secure
# as an implementation: it makes no effort at mitigating side-channel
# leaks (e.g. computation time). It is also not much optimized. The
# intended usage is production of test vectors, and exploration of
# addition formulas. Do NOT use it in production code.
#
# This file contains several classes and variables. In appearance order:
#
#   Zmod                     generic class for computing modulo a given integer
#
#   GF255e, GF255s           base fields for curve jq255e and jq255s
#
#   Scalar255e, Scalar255s   fields for scalars (integers modulo the group
#                            order, which is prime)
#
#   Jq255Curve               base class for curve instances
#
#   Jq255e, Jq255s           instances for the two curves jq255e and jq255s
#
# All this code is meant for Python 3.4+.

# =========================================================================
# Custom implementation of modular integers.
#
# This mimics Sage syntax. For a modulus m, the ring of integers modulo
# m is defined as Zmod(m). A value is obtained by "calling" (function
# call syntax) the ring on an integer (or anything that can be
# transtyped into an integer); that integer is internally reduced.
# Values are immutable. When converted to a string or formatted, they
# behave like plain integers with a value in the 0..m-1 range.
#
# Inversion works only for an odd modulus. Square root extraction works
# only for a prime modulus equal to 3, 5 or 7 modulo 8 (i.e. an odd prime
# which is not equal to 1 modulo 8); if the modulus is not prime, then
# incorrect results will be returned.

class Zmod:
    def __init__(self, m):
        """
        Initialize for the provided modulus. The modulus must be convertible
        to a positive integer of value at least 2.
        """
        m = int(m)
        if m < 2:
            raise Exception('invalid modulus')
        self.m = m
        self.encodedLen = (m.bit_length() + 7) >> 3
        self.zero = Zmod.Element(self, 0)
        self.one = Zmod.Element(self, 1)
        self.minus_one = Zmod.Element(self, m - 1)

    def __call__(self, x):
        """
        Make a ring element. If x is already an element of this ring,
        then it is returned as is. Otherwise, x is converted to an integer,
        which is reduced modulo the ring modulus, and used to make a new
        value.
        """
        if isinstance(x, Zmod.Element) and (x.ring is self):
            return x
        return Zmod.Element(self, int(x) % self.m)

    def Decode(self, bb):
        """
        Decode an element from bytes (exactly the number of bytes matching
        the modulus length). Unsigned little-endian convention is used.
        If the value is not lower than the modulus, an exception is thrown.
        """
        if len(bb) != self.encodedLen:
            raise Exception('Invalid encoded value (wrong length = {0})'.format(len(bb)))
        x = int.from_bytes(bb, byteorder='little')
        if x >= self.m:
            raise Exception('Invalid encoded value (not lower than modulus)')
        return Zmod.Element(self, x)

    def DecodeReduce(self, bb):
        """
        Decode an element from bytes. All provided bytes are read, in
        unsigned little-endian convention; the value is then reduced
        modulo the ring modulus.
        """
        x = int.from_bytes(bb, byteorder='little')
        return Zmod.Element(self, x % self.m)

    class Element:
        def __init__(self, ring, value):
            self.ring = ring
            self.x = int(value)

        def __getattr__(self, name):
            if name == 'modulus':
                return self.ring.m
            else:
                raise AttributeError()

        def __int__(self):
            """
            Conversion to an integer returns the value in the 0..m-1 range.
            """
            return self.x

        def valueOfOther(self, b):
            if isinstance(b, Zmod.Element):
                if self.ring is b.ring:
                    return b.x
                if self.ring.m != b.ring.m:
                    raise Exception('ring mismatch')
                return b.x
            elif isinstance(b, int):
                return b % self.ring.m
            else:
                return False

        def __add__(self, b):
            b = self.valueOfOther(b)
            if b is False:
                return NotImplemented
            return self.ring(self.x + b)

        def __radd__(self, b):
            b = self.valueOfOther(b)
            if b is False:
                return NotImplemented
            return self.ring(b + self.x)

        def __sub__(self, b):
            b = self.valueOfOther(b)
            if b is False:
                return NotImplemented
            return self.ring(self.x - b)

        def __rsub__(self, b):
            b = self.valueOfOther(b)
            if b is False:
                return NotImplemented
            return self.ring(b - self.x)

        def __neg__(self):
            return self.ring(-self.x)

        def __mul__(self, b):
            b = self.valueOfOther(b)
            if b is False:
                return NotImplemented
            return self.ring(self.x * b)

        def __rmul__(self, b):
            b = self.valueOfOther(b)
            if b is False:
                return NotImplemented
            return self.ring(b * self.x)

        def __truediv__(self, y):
            # This function works only if the modulus is odd.
            # If the divisor is not invertible, then we return 0.
            #
            # We use a binary GCD. Invariants:
            #   a*x = u*y mod m
            #   b*x = v*y mod m
            # The GCD ends with b = 1, in which case v = x/y mod m.
            a = self.valueOfOther(y)
            if a is False:
                return NotImplemented
            m = self.ring.m
            if (m & 1) == 0:
                raise Exception('Unsupported division: even modulus')
            b = m
            u = self.x
            v = 0
            while a != 0:
                if (a & 1) == 0:
                    a >>= 1
                    if (u & 1) != 0:
                        u += m
                    u >>= 1
                else:
                    if a < b:
                        a, b = b, a
                        u, v = v, u
                    a -= b
                    if u < v:
                        u += m
                    u -= v
            # Note: if the divisor is zero, then we immediately arrive
            # here with v = 0, which is what we want.
            return self.ring(v)

        def __rtruediv__(self, y):
            return self.ring(y).__truediv__(self)

        def __floordiv__(self, y):
            return self.__truediv__(y)

        def __rfloordiv__(self, y):
            return self.ring(y).__truediv__(self)

        def __pow__(self, e):
            # We do not assume that the modulus is prime; therefore, we
            # cannot reduce the exponent modulo m-1.
            e = int(e)
            if e == 0:
                return self.ring.one
            t = self
            if e < 0:
                t = t.ring.one / t
                e = -e
            r = self
            elen = e.bit_length()
            for i in range(0, elen - 1):
                j = elen - 2 - i
                r *= r
                if ((e >> j) & 1) != 0:
                    r *= self
            return r

        def __lshift__(self, n):
            n = int(n)
            if n < 0:
                raise Exception('negative shift count')
            return self.ring(self.x << n)

        def __rshift__(self, n):
            n = int(n)
            if n < 0:
                raise Exception('negative shift count')
            m = self.ring.m
            if (m & 1) == 0:
                raise Exception('Unsupported right shift: even modulus')
            t = self.x
            while n > 0:
                if (t & 1) != 0:
                    t += m
                t >>= 1
                n -= 1
            return self.ring(t)

        def __eq__(self, b):
            if isinstance(b, Zmod.Element):
                if self.ring.m != b.ring.m:
                    return False
                return self.x == b.x
            else:
                return self.x == int(b)

        def __ne__(self, b):
            if isinstance(b, Zmod.Element):
                if self.ring.m != b.ring.m:
                    return True
                return self.x != b.x
            else:
                return self.x != int(b)

        def __repr__(self):
            return self.x.__repr__()

        def __str__(self):
            return self.x.__str__()

        def __format__(self, fspec):
            return self.x.__format__(fspec)

        def __bytes__(self):
            return self.x.to_bytes(self.ring.encodedLen, byteorder='little')

        def sqrt(self):
            """
            Compute a square root of the current value. If the value is
            not a square, this returns False. The returned square root is
            normalized: its least significant bit (as an integer in the
            0..m-1 range) is zero.

            WARNING: square root extraction assumes that the modulus is
            a prime integer. It works only for a modulus equal to 3, 5
            or 7 modulo 8.
            """
            m = self.ring.m
            if (m & 3) == 3:
                s = self**((m + 1) >> 2)
            elif (m & 7) == 5:
                # Atkin's formulas:
                #   b <- (2*a)^((m-5)/8)
                #   c <- 2*a*b^2
                #   return a*b*(c - 1)
                b = (self << 1)**((m - 5) >> 3)
                c = (self*b*b) << 1
                s = self*b*(c - 1)
            else:
                raise Exception('Unsupported square root for this modulus')
            if (s * s).x != self.x:
                return False
            if (s.x & 1) != 0:
                s = -s
            return s

        def is_zero(self):
            return self.x == 0

        def is_square(self):
            # This function works only if the modulus is odd.
            #
            # This is a Legendre/Jacobi symbol, that follows the same
            # reduction steps as a binary GCD.
            m = self.ring.m
            if (m & 1) == 0:
                raise Exception('Unsupported division: even modulus')
            a = self.x
            b = m
            if a == 0:
                return True
            ls = 1
            while a != 0:
                if (a & 1) == 0:
                    a >>= 1
                    if ((b + 2) & 7) > 4:
                        ls = -ls
                else:
                    if a < b:
                        a, b = b, a
                        if (a & b & 3) == 3:
                            ls = -ls
                    a -= b
            return ls == 1

        def is_negative(self):
            """
            Test whether this value is "negative". A field element is
            formally declared negative if its representation as an
            integer in the 0 to m-1 range (with m being the field
            modulus) is an odd integer.
            """
            return (self.x & 1) != 0

# =========================================================================
# Concrete fields:
#
#   GF255e       field for jq255e point coordinates; modulus m = 2^255 - 18651
#
#   Scalar255e   field for integers modulo the jq255e group prime order:
#                r = 2^254 - 131528281291764213006042413802501683931
#
#   GF255s       field for jq255s point coordinates; modulus m = 2^255 - 3957
#
#   Scalar255s   field for integers modulo the jq255s group prime order:
#                r = 2^254 + 56904135270672826811114353017034461895

GF255e = Zmod(2**255 - 18651)
Scalar255e = Zmod(2**254 - 131528281291764213006042413802501683931)
GF255s = Zmod(2**255 - 3957)
Scalar255s = Zmod(2**254 + 56904135270672826811114353017034461895)

# =========================================================================
# Curves and points:
#
# An instance of Jq255Curve represents one of the curves, or, more
# accurately, the prime order group defined out of the curve. Group
# elements ('points') are points on the curve that are part of that
# subgroup. Each point instance is immutable. A new point instance is
# obtained by calling an appropriate method on the Jq255Curve instance,
# or by using the functions and operators on existing points.

class Jq255Curve:
    def __init__(self, name):
        if name == 'jq255e' or name == 'Jq255e':
            name = 'jq255e'
            self.dname = 'Jq255e'
            self.bname = b'jq255e'
            self.K = GF255e
            self.SF = Scalar255e
            self.a = self.K(0)
            self.b = self.K(-2)
            self.eta = self.K(-1).sqrt()
            Gx = self.K(2)
            Gu = self.K(1)
        elif name == 'jq255s' or name == 'Jq255s':
            name = 'jq255s'
            self.dname = 'Jq255s'
            self.bname = b'jq255s'
            self.K = GF255s
            self.SF = Scalar255s
            self.a = self.K(-1)
            self.b = self.K(1)/2
            self.nonQR = self.K(-1)
            Gx = self.K(26116555989003923291153849381583511726884321626891190016751861153053671511729)
            Gu = self.K(3)
        else:
            raise Exception('Unknown curve: {0}'.format(name))
        self.name = name
        self.ap = -2*self.a
        self.bp = self.a**2 - 4*self.b
        self.encodedLen = self.K.encodedLen
        self.N = Jq255Curve.Point(self, self.K.minus_one, self.K.one, self.K.zero, self.K.zero)
        GZ = Gx**2 + self.a*Gx + self.b
        self.G = Jq255Curve.Point(self, Gx**2 - self.b, GZ, Gu*GZ, (Gu**2)*GZ)

    def __call__(self, e, u):
        """
        Instantiate a point from its (e,u) coordinates. The two provided
        values are converted to field elements, and they are verified to
        match the curve equation.
        """
        e = self.K(e)
        u = self.K(u)
        if e**2 != self.bp*u**4 + self.ap*u**2 + self.K.one:
            raise Exception('Invalid coordinates')
        return Jq255Curve.Point(self, e, self.K.one, u, u**2)

    def Decode(self, bb):
        """
        Decode 32 bytes (bb) into a point. This function enforces canonical
        representation.
        """
        u = self.K.Decode(bb)
        t = u**2
        d = self.bp*(t**2) + self.ap*t + self.K.one
        e = d.sqrt()
        if e is False:
            raise Exception('Invalid encoded point')
        # Test disabled: Zmod.sqrt() already returns the non-negative root
        # if e.is_negative():
        #     e = -e
        return Jq255Curve.Point(self, e, self.K.one, u, t)

    # Field-to-group map, for jq255e.
    def map_to_jq255e(self, f):
        if f.is_zero():
            return self.N
        x1 = 4*(f**2) - 7
        x2 = (4*(f**2) + 7)*self.eta  # self.eta = sqrt(-1) (non-negative root)
        x0 = 4*f
        z1 = 64*(f**7) + 176*(f**5) - 308*(f**3) - 343*f
        z2 = -self.eta*(64*(f**7) - 176*(f**5) - 308*(f**3) + 343*f)
        y0 = 8*(f**2)
        if z1.is_square():
            (x, xx, y, yy) = (x1, x0, z1.sqrt(), y0)
        elif z2.is_square():
            (x, xx, y, yy) = (x2, x0, z2.sqrt(), y0)
        else:
            (x, xx, y, yy) = (x1*x2, x0**2, (z1*z2).sqrt(), y0**2)
        (u, uu) = (x*yy, xx*y)
        (X, XX) = (-8*(u**2), uu**2)
        (U, UU) = (2*x*xx*uu, u*(x**2 - 8*(xx**2)))
        (E, EE) = (X**2 + 2*(XX**2), X**2 - 2*(XX**2))
        return Jq255Curve.Point(self, E*(UU**2), EE*(UU**2), U*UU*EE, (U**2)*EE)

    # Field-to-group map, for jq255s.
    def map_to_jq255s(self, f):
        GFq = self.K
        if f == GFq.one or f == GFq.minus_one:
            return self.N
        z1 = -2*(f**6) + 14*(f**4) - 14*(f**2) + 2
        z2 = -z1*(f**2)
        xx = 1 - f**2
        if z1.is_square():
            (x, y) = (GFq(-2), z1.sqrt())
        else:
            (x, y) = (2*(f**2), -z2.sqrt())
        if y.is_zero():
            return self.N
        (u, uu) = (x*xx, y)
        (X, XX) = (2*(u**2), uu**2)
        (U, UU) = (2*uu, x**2 + xx**2)
        (s1, s2) = (X*(2*X - XX), XX*(X - XX))
        (E, EE) = (s1 + s2, s1 - s2)
        return Jq255Curve.Point(self, E*(UU**2), EE*(UU**2), U*UU*EE, (U**2)*EE)

    def MapToCurve(self, bb):
        """
        Map the provided bytes into a field element (by decoding the
        bytes into an integer with unsigned little-endian convention,
        then reducing the integer modulo the field order), then the
        field into a group element. Output distribution is not uniform;
        for a proper hash-to-group operation, see HashToCurve().
        """
        f = self.K(int.from_bytes(bb, byteorder='little'))
        if self.name == 'jq255e':
            return self.map_to_jq255e(f)
        elif self.name == 'jq255s':
            return self.map_to_jq255s(f)
        else:
            raise Exception('Field-to-group unimplemented for this curve')

    # Points internally use extended (E:Z:U:T) coordinates, with:
    #    e == E/Z   u == U/Z   u^2 == T/Z   Z != 0
    class Point:
        def __init__(self, curve, E, Z, U, T):
            self.curve = curve
            self.E = E
            self.Z = Z
            self.U = U
            self.T = T

        def is_neutral(self):
            """
            Return True for the neutral element, False otherwise.
            """
            return self.U.is_zero()

        def coordinatesOfOther(self, other):
            if isinstance(other, Jq255Curve.Point):
                if self.curve is other.curve:
                    return (other.E, other.Z, other.U, other.T)
            raise Exception('Curve mismatch')

        def __add__(self, other):
            (E1, Z1, U1, T1) = self.E, self.Z, self.U, self.T
            (E2, Z2, U2, T2) = self.coordinatesOfOther(other)
            ap = self.curve.ap
            bp = self.curve.bp
            e1e2 = E1*E2
            z1z2 = Z1*Z2
            u1u2 = U1*U2
            t1t2 = T1*T2
            tz = (Z1 + T1)*(Z2 + T2) - z1z2 - t1t2
            eu = (E1 + U1)*(E2 + U2) - e1e2 - u1u2
            hd = z1z2 - bp*t1t2
            E3 = (z1z2 + bp*t1t2)*(e1e2 + ap*u1u2) + 2*bp*u1u2*tz
            Z3 = hd**2
            T3 = eu**2
            U3 = ((hd + eu)**2 - Z3 - T3) >> 1
            return Jq255Curve.Point(self.curve, E3, Z3, U3, T3)

        def __neg__(self):
            return Jq255Curve.Point(self.curve, self.E, self.Z, -self.U, self.T)

        def __sub__(self, other):
            return self + (-other)

        def inner_xdouble_jq255e(self, k):
            (E, Z, U, T) = (self.E, self.Z, self.U, self.T)

            # P (EZUT) -> 2*P (XWJ)
            s = E**2
            X = s**2
            W = 2*(Z**2) - s
            J = 2*(E*U)

            # k-1 times P (XWJ) -> 2*P (XWJ)
            for _ in range(1, k):
                s1 = W**2
                s2 = s1 - 2*X
                s3 = s2**2
                X = s3**2
                J = J*((W + s2)**2 - s1 - s3)   # Alternatively: J = 2*J*W*s2
                W = s3 - 2*(s1**2)

            # Conversion XWJ -> EZUT
            Z = W**2
            T = J**2
            U = ((W + J)**2 - Z - T) >> 1       # Alternatively: U = J*W
            E = 2*X - Z
            return Jq255Curve.Point(self.curve, E, Z, U, T)

        def inner_xdouble_jq255s(self, k):
            (E, Z, U, T) = (self.E, self.Z, self.U, self.T)

            # P (EZUT) -> 2*P+N (XWJ)
            s = U**2
            X = 8*(s**2)
            W = 2*s - (T + Z)**2
            J = 2*(E*U)

            # k-1 times P (XWJ) -> 2*P+N (XWJ)
            for _ in range(1, k):
                s1 = W*J
                s2 = s1**2
                s3 = (W + J)**2 - 2*s1
                J = 2*s1*(2*X - s3)
                X = 8*(s2**2)
                W = 2*s2 - s3**2

            # Conversion XWJ -> EZUT
            Z = W**2
            T = J**2
            U = ((W + J)**2 - Z - T) >> 1       # Alternatively: U = J*W
            E = 2*X - Z - T
            return Jq255Curve.Point(self.curve, E, Z, U, T)

        def Double(self):
            """
            Compute the double of this point.
            """
            return self.Xdouble(1)

        def Xdouble(self, k):
            """
            Return (2^k)*self (k successive doublings).
            """
            if self.curve.name == 'jq255e':
                return self.inner_xdouble_jq255e(k)
            elif self.curve.name == 'jq255s':
                return self.inner_xdouble_jq255s(k)
            else:
                raise Exception('Xdouble() is not implemented for this curve.')
            (E, Z, U, T) = P
            return Jq255Curve.Point(self.curve, E, Z, U, T)

        def __mul__(self, n):
            # Make sure the scalar is in the proper field of scalars. This
            # ensures modular reduction if the source value is an integer.
            if isinstance(n, Zmod.Element) and (n.ring is self.curve.SF):
                s = int(n)
            else:
                s = int(self.curve.SF(n))

            # Build window: win[i - 1] = i*P  (with i = 1 to 16)
            win = []
            win.append(self)
            for i in range(2, 16, 2):
                P2 = win[(i >> 1) - 1].Double()
                P3 = self + P2
                win.append(P2)
                win.append(P3)
            win.append(self + win[14])

            # Booth recoding of the scalar with a 5-bit window
            j = int(s)
            sd = []
            cc = 0
            for i in range(0, 51):
                nd = (j & 31) + cc
                j >>= 5
                if nd > 16:
                    sd.append(nd - 32)
                    cc = 1
                else:
                    sd.append(nd)
                    cc = 0

            # Point multiplication itself
            if sd[50] == 0:
                R = self.curve.N
            else:
                R = win[sd[50] - 1]
            for i in reversed(range(0, 50)):
                if sd[i] > 0:
                    Q = win[sd[i] - 1]
                elif sd[i] < 0:
                    Q = -win[(-sd[i]) - 1]
                else:
                    Q = self.curve.N
                R = R.Xdouble(5) + Q
            return R

        def __rmul__(self, n):
            return self * n

        def __eq__(self, other):
            (E1, Z1, U1, T1) = self.E, self.Z, self.U, self.T
            (E2, Z2, U2, T2) = self.coordinatesOfOther(other)
            return U1*E2 == U2*E1

        def __ne__(self, other):
            (E1, Z1, U1, T1) = self.E, self.Z, self.U, self.T
            (E2, Z2, U2, T2) = self.coordinatesOfOther(other)
            return U1*E2 != U2*E1

        def eu(self):
            """
            Get the (e,u) coordinates of a point representing this
            group element. Each element has two possible representations
            as a point, exactly one of which has a non-negative coordinate
            e; this is the one which is returned here.
            """
            iZ = 1/self.Z
            e = self.E*iZ
            u = self.U*iZ
            if e.is_negative():
                e, u = -e, -u
            return (e, u)

        def __getattr__(self, name):
            if name == 'e':
                e, u = self.eu()
                return e
            elif name == 'u':
                e, u = self.eu()
                return u
            raise AttributeError()

        def __repr__(self):
            (e, u) = self.eu()
            return '{0}({1}, {2})'.format(self.curve.dname, e, u)

        def __bytes__(self):
            (e, u) = self.eu()
            return bytes(u)

# =========================================================================
# Concrete curves:
#
#   Jq255e    equation y^2 = x*(x^2 - 2) in field GF(2^255-18651)
#                      e^2 = 8*u^4 + 1
#
#   Jq255s    equation y^2 = x*(x^2 - x + 1/2) in field GF(2^255-3957)
#                      e^2 = -u^4 + 2*u^2 + 1

Jq255e = Jq255Curve('jq255e')
Jq255s = Jq255Curve('jq255s')

# =========================================================================
# High-level cryptographic algorithms.
#
# We define key exchange (ECDH) and signatures (Schnorr) on top of
# both jq255e and jq255s.
#
# Noteworthy details:
#
#  - A private key is an integer in the 1..r-1 range. A private key is
#    encoded over 32 bytes. When decoding, all bits are taken into
#    account (no ignored bit). Out-of-range values are rejected when
#    decoding. Note that 0 is not a valid private key.
#
#  - A public key is a point. It encodes into 32 bytes. When decoding, all
#    bits are taken into account (no ignored bit). Canonical encoding is
#    enforced: a given curve point can be validly encoded in only one way.
#    The group neutral (N, encoded as a sequence of bytes of value 0x00)
#    is not a valid public key; such a value MUST be rejected if
#    encountered when decoding.
#
#  - An ECDH message is a public key. It follows the rules of public keys,
#    as stated above. Thus, it cannot be a neutral point.
#
#  - A signature is the concatenation of a challenge value (16 bytes)
#    and a scalar (32 bytes). The scalar follows the same rules as the
#    private key, except that the value 0 is valid. The challenge is
#    interpreted as an integer in the 0 to 2^128-1 range, using the
#    unsigned little-endian encoding convention. Out of range values for
#    the scalar MUST still be rejected, and there is no ignored bit.
#
#  - Since the group has prime order, there is no ambiguousness about
#    the signature verification equation.

import hashlib
import os

def Keygen(curve, sh = None):
    """
    Generate a new keypair. If sh is provided, then it must be an object
    that implements a function digest(len), that outputs 'len' bytes,
    and can be invoked repeatedly if needed to get more bytes. An
    instance of SHAKE128 or SHAKE256, already loaded with a random seed,
    is appropriate. If sh is not provided (or is None), then the
    OS-provided random generator (os.urandom()) is used.

    Returned value is the private key (as a scalar instance).
    """
    if sh == None:
        while True:
            bb = os.urandom(curve.encodedLen)
            sk = curve.SF.DecodeReduce(bb)
            if not(sk.is_zero()):
                return sk
    else:
        j = 0
        while True:
            bb = sh.digest(curve.encodedLen * (j + 1))
            sk = curve.SF.DecodeReduce(bb[curve.encodedLen * j:])
            if not sk.is_zero():
                return sk
            j += 1

def EncodePrivate(sk):
    """
    Encode a private key into bytes (exactly 32 bytes for both
    jq255e and jq255s).
    """
    return bytes(sk)

def DecodePrivate(curve, bb):
    """
    Decode a private key from bytes. Note that the length must match the
    expected value (32 bytes for both jq255e and jq255s) and the value
    is verified to be in the proper range (1 to r-1, with r being the
    prime order of the jq255* group).
    """
    sk = curve.SF.Decode(bb)
    if sk.is_zero():
        raise Exception('Invalid private key (zero)')
    return sk

def MakePublic(curve, sk):
    """
    Make a public key (curve point) out of a private key.
    """
    return curve.G * sk

def EncodePublic(pk):
    """
    Encode a public key into bytes.
    """
    return bytes(pk)

def DecodePublic(curve, bb):
    """
    Decode a public key from bytes. Invalid points are rejected. The
    neutral element is NOT accepted as a public key.
    """
    pk = curve.Decode(bb)
    if pk.is_neutral():
        raise Exception('Invalid public key (neutral point)')
    return pk

def ECDH(sk, pk, peer_pk):
    """
    Do an ECDH key exchange. sk is our private key; pk is the matching
    public key (normally generated from sk with makePublic()). peer_pk
    is the public key received from the peer.

    peer_pk may be either a decoded point (from decodePublic()), or
    directly the received bytes (as an array of bytes or a 'bytes' object).
    If peer_pk is a decoded point, on the same curve as our public key,
    and not the neutral point, then the process cannot fail.

    If peer_pk is provided in encoded format (as bytes), then this
    function decodes it internally. Upon decoding failure, or if the
    bytes encode the neutral point, which is not a valid public key,
    then the alternate key derivation is used: the ECDH() function does
    not fail, but instead generates a secret key in a way which is
    deterministic from the exchanged public values, and our private key.
    External attackers cannot distinguish between a success or a
    failure; this is meant for some (rare) protocols in which exchanged
    points are masked, and outsiders shall not be able to find out
    whether a given sequence of bytes is the masked value of a proper
    point or not.

    Returned value are:
       (key, ok)
    with:
       key   the generated secret, of length 32 bytes
       ok    boolean, True for success, False for failure
    """
    curve = pk.curve
    enc_peer_pk = bytes(peer_pk)
    peer_pk_good = True
    if isinstance(peer_pk, Jq255Curve.Point):
        if not(pk.curve is peer_pk.curve):
            raise Exception('Curve mismatch in ECDH')
        if pk.is_neutral():
            raise Exception('Peek public key is invalid (neutral element)')
    else:
        # We are going to decode the public key bytes. In that mode,
        # failures should trigger the alternate key derivation feature,
        # instead of being reported as exceptions. This implementation
        # is not constant-time, and the exception-catching process below
        # may leak to outsider through timing-based side channels that
        # the received bytes were not a valid public key; in a
        # production-level secure implementation, this side channel
        # should be avoided as well.
        try:
            peer_pk = pk.curve.Decode(enc_peer_pk)
            if peer_pk.is_neutral():
                raise Exception('key is neutral')
        except Exception:
            peer_pk_good = False
            peer_pk = curve.G

    # The ECDH core: multiply the peer point by our private key.
    # The shared secret is the _square_ of the w coordinate of the result
    # (a square is used to make ECDH implementable with a ladder
    # algorithm that avoids full decoding of the input point).
    P = peer_pk * sk

    # For key generation, we want to use the digest over the concatenation of:
    #   - the two public keys;
    #   - a byte of value 0x53 (on success) or 0x46 (on failure, because the
    #     provided peer key bytes are not the valid encoding of a valid
    #     public key);
    #   - the shared secret (our own private key on failure).
    # We order the public keys by interpreting them as integers
    # (big-endian convention) so that both parties use the same order
    # (equivalently, the two keys are ordered lexicographically).
    pk1 = bytes(pk)
    ipk1 = int.from_bytes(pk1, byteorder='big')
    pk2 = enc_peer_pk
    ipk2 = int.from_bytes(pk2, byteorder='big')
    if ipk1 > ipk2:
        (pk1, pk2) = (pk2, pk1)

    sh = hashlib.blake2s()
    sh.update(pk1)
    sh.update(pk2)
    if peer_pk_good:
        sh.update(b'\x53')
        sh.update(bytes(P))
    else:
        sh.update(b'\x46')
        sh.update(bytes(sk))
    return (sh.digest(), peer_pk_good)

# Defined hash function names.
HASHNAME_SHA224      = b'sha224'
HASHNAME_SHA256      = b'sha256'
HASHNAME_SHA384      = b'sha384'
HASHNAME_SHA512      = b'sha512'
HASHNAME_SHA512_224  = b'sha512224'
HASHNAME_SHA512_256  = b'sha512256'
HASHNAME_SHA3_224    = b'sha3224'
HASHNAME_SHA3_256    = b'sha3256'
HASHNAME_SHA3_384    = b'sha3384'
HASHNAME_SHA3_512    = b'sha3512'
HASHNAME_BLAKE2B     = b'blake2b'
HASHNAME_BLAKE2S     = b'blake2s'

# Normalize a hash function name:
#   An empty string (binary or not) is converted to None
#   A non-empty text string is encoded into UTF-8
def normalize_hash_name(hashname):
    if hashname is None or hashname == '' or hashname == b'':
        return None
    if isinstance(hashname, str):
        hashname = bytes(hashname, encoding='utf-8')
    if not(isinstance(hashname, bytes)):
        raise Exception('Invalid object type for a hash function name')
    return hashname

# Prepare the message; if hashname is None or empty, then this is a
# raw input, otherwise hv is pre-hashed data with the specified hash
# function.
def prepare_message(hv, hashname):
    hashname = normalize_hash_name(hashname)
    if hashname is None:
        return b'\x52' + hv
    else:
        return b'\x48' + hashname + b'\x00' + hv

def generate_nonce(sk, pk, M, seed):
    sh = hashlib.blake2s()
    sh.update(bytes(sk))
    sh.update(bytes(pk))
    sh.update(len(seed).to_bytes(8, byteorder='little'))
    sh.update(seed)
    sh.update(M)
    bb = sh.digest()
    return pk.curve.SF(int.from_bytes(bb, byteorder='little'))

def make_challenge(R, pk, M):
    sh = hashlib.blake2s()
    sh.update(bytes(R))
    sh.update(bytes(pk))
    sh.update(M)
    return sh.digest()[0:16]  # 32-byte output is truncated to 16 bytes

def sign_inner(sk, pk, M, seed):
    curve = pk.curve
    k = generate_nonce(sk, pk, M, seed)
    R = k*curve.G
    c = make_challenge(R, pk, M)
    ic = int.from_bytes(c, byteorder='little')
    s = k + sk*curve.SF(ic)
    return c + bytes(s)       # Concatenation of c and encoded s

def verify_inner(pk, sig, M):
    curve = pk.curve
    if len(sig) != 48:
        return False
    c = sig[0:16]
    try:
        s = curve.SF.Decode(sig[16:48])  # Throws an exception on decode error
    except Exception:
        return False
    cc = curve.SF(int.from_bytes(c, byteorder='little'))
    R = s*curve.G - cc*pk
    c2 = make_challenge(R, pk, M)
    return c == c2       # Comparison of two 16-byte sequences

def Sign(sk, pk, hashname, hv, seed = b''):
    """
    Sign the provided (hashed) data 'hv'. The signer's private (sk) and
    public (pk) keys are used. The data is assumed to have been hashed
    with the hash function identified by 'hashname' (hash function names
    are lowercase and use no punctuation, e.g. 'sha256' for SHA-256);
    if the input data provided as 'hv' is the raw unhashed data, then
    'hashname' should be None or an empty string. Binary strings can also
    be used as hash function names.

    Using raw data makes the signature engine resilient to collision
    attacks on hash functions, but it also makes streamed processing
    harder for memory-constrained systems. Using a collision-resistant
    hash function (e.g. BLAKE2s or SHA3-256) is recommended.

    The 'seed' is an optional binary string that can augment the internal
    generation of the per-secret signature. Without a seed, deterministic
    generation is used, which is safe. An extra non-constant seed value
    (which needs not be random) makes signatures randomized; it can also
    provide some extra resilience against fault attacks (of course, if
    fault attacks are an issue, then side channels are also an issue,
    and this reference implementation shall not be used since it is not
    resistant to side channels).
    """
    return sign_inner(sk, pk, prepare_message(hv, hashname), seed)

def Verify(pk, sig, hashname, hv):
    """
    Verify the signature 'sig' (bytes) over the provided (hashed) data
    'hv' (hashed with the function identified by 'hashname'; use None or
    the empty string b'' if data is unhashed) against the public key pk.
    Returned value is True on success (signature is valid for this
    public key and that data), False otherwise.
    """
    return verify_inner(pk, sig, prepare_message(hv, hashname))

def HashToCurve(curve, hashname, hv):
    """
    Hash the provided input data into a curve point. The data (hv) is
    either raw unhashed data, or a hash value if the data was pre-hashed.
    'hash_name' identifies the hash function used for pre-hashing; use None
    or b'' (empty string) for raw unhashed data. Returned point can be any
    point on the group, including the neutral N.
    """
    M = prepare_message(hv, hashname)
    sh = hashlib.blake2s()
    sh.update(b'\x01')      # One byte of value 0x01
    sh.update(M)
    bb1 = sh.digest()
    sh = hashlib.blake2s()
    sh.update(b'\x02')      # One byte of value 0x02
    sh.update(M)
    bb2 = sh.digest()
    return curve.MapToCurve(bb1) + curve.MapToCurve(bb2)
