use std::mem::ManuallyDrop;
use std::ptr::NonNull;
use std::slice;

pub struct Shape(Vec<usize>);

impl From<Vec<usize>> for Shape {
    fn from(vec: Vec<usize>) -> Self {
        Self(vec)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct OwnedRepr<T>
{
    ptr: NonNull<T>,
    len: usize,
    capacity: usize,
}

impl<A> OwnedRepr<A> {
    pub fn from(v: Vec<A>) -> Self
    {
        let mut v = ManuallyDrop::new(v);
        let len = v.len();
        let capacity = v.capacity();
        unsafe {
            let ptr = NonNull::new_unchecked(v.as_mut_ptr());
            Self { ptr, len, capacity }
        }
    }

    pub(crate) fn into_vec(self) -> Vec<A>
    {
        ManuallyDrop::new(self).take_as_vec()
    }

    pub(crate) fn as_slice(&self) -> &[A]
    {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub(crate) fn len(&self) -> usize
    {
        self.len
    }

    pub(crate) fn as_ptr(&self) -> *const A
    {
        self.ptr.as_ptr()
    }

    pub(crate) fn as_nonnull_mut(&mut self) -> NonNull<A>
    {
        self.ptr
    }

    fn take_as_vec(&mut self) -> Vec<A>
    {
        let capacity = self.capacity;
        let len = self.len;
        self.len = 0;
        self.capacity = 0;
        unsafe { Vec::from_raw_parts(self.ptr.as_ptr(), len, capacity) }
    }
}

pub struct Array<T>
where
    T: ArrayElement,
{
    shape: Shape,
    data: OwnedRepr<T>,
}

impl<T: ArrayElement> Array<T> {
    fn ndim(&self) -> usize {
        self.shape.0.len()
    }

    fn dim(&self, index: usize) -> Option<usize> {
        if index < self.shape.0.len() {
            Some(self.shape.0[index])
        } else {
            None
        }
    }

    fn from(v: Vec<T>) -> Self
    {
        Self::from_shape_vec_unchecked(vec![v.len()], v)
    }

    pub fn from_shape_vec_unchecked<Sh>(shape: Sh, v: Vec<T>) -> Self
    where
        Sh: Into<Shape>,
    {
        Array {
            shape: shape.into(),
            data: OwnedRepr::from(v),
        }
    }
}

pub trait ArrayElement: Copy + 'static {}
impl ArrayElement for f64 {}


